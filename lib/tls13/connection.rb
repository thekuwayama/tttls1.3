# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  INITIAL = 0
  EOF     = -1

  # rubocop: disable Metrics/ClassLength
  class Connection
    # @param socket [Socket]
    def initialize(socket)
      @socket = socket
      @endpoint = nil # Symbol or String, :client or :server
      @key_schedule = nil # TLS13::KeySchedule
      @priv_keys = {} # Hash of NamedGroup => OpenSSL::PKey::$Object
      @read_cipher = Cryptograph::Passer.new
      @write_cipher = Cryptograph::Passer.new
      @transcript = Transcript.new
      @message_queue = [] # Array of TLS13::Message::$Object
      @binary_buffer = '' # deposit Record.surplus_binary
      @cipher_suite = nil # TLS13::CipherSuite
      @notyet_application_secret = true
      @state = 0 # ClientState or ServerState
      @send_record_size = Message::DEFAULT_RECORD_SIZE_LIMIT
      @psk = nil # String
    end

    # @raise [TLS13::Error::ConfigError]
    #
    # @return [String]
    def read
      # secure channel has not established yet
      raise Error::ConfigError \
        unless @endpoint == :client && @state == ClientState::CONNECTED
      return '' if @state == EOF

      message = nil
      loop do
        message = recv_message
        # At any time after the server has received the client Finished
        # message, it MAY send a NewSessionTicket message.
        break unless message.is_a?(Message::NewSessionTicket)

        process_new_session_ticket(message)
      end
      return '' if message.nil?

      message.fragment
    end

    # @return [Boolean]
    def eof?
      @state == EOF
    end

    # @param binary [String]
    #
    # @raise [TLS13::Error::ConfigError]
    def write(binary)
      # secure channel has not established yet
      raise Error::ConfigError \
        unless @endpoint == :client && @state == ClientState::CONNECTED

      ap = Message::ApplicationData.new(binary)
      send_application_data(ap, @write_cipher)
    end

    def close
      send_alert(:close_notify)
      @state = EOF

      nil
    end

    private

    # @param cipher_suite [TLS13::CipherSuite]
    # @param write_key [String]
    # @param write_iv [String]
    #
    # @return [TLS13::Cryptograph::Aead]
    def gen_cipher(cipher_suite, write_key, write_iv)
      seq_num = SequenceNumber.new
      Cryptograph::Aead.new(
        cipher_suite: cipher_suite,
        write_key: write_key,
        write_iv: write_iv,
        sequence_number: seq_num
      )
    end

    # @param type [TLS13::Message::ContentType]
    # @param messages [Array of TLS13::Message::$Object] handshake messages
    # @param write_cipher [TLS13::Cryptograph::Aead]
    def send_handshakes(type, messages, write_cipher)
      record = Message::Record.new(
        type: type,
        messages: messages,
        cipher: write_cipher
      )
      send_record(record)
    end

    def send_ccs
      ccs_record = Message::Record.new(
        type: Message::ContentType::CCS,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [Message::ChangeCipherSpec.new],
        cipher: Cryptograph::Passer.new
      )
      send_record(ccs_record)
    end

    # @param message [TLS13::Message::ApplicationData]
    # @param write_cipher [TLS13::Cryptograph::Aead]
    def send_application_data(message, write_cipher)
      ap_record = Message::Record.new(
        type: Message::ContentType::APPLICATION_DATA,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [message],
        cipher: write_cipher
      )
      send_record(ap_record)
    end

    # @param symbol [Symbol] key of ALERT_DESCRIPTION
    def send_alert(symbol)
      message = Message::Alert.new(
        description: Message::ALERT_DESCRIPTION[symbol]
      )
      type = Message::ContentType::ALERT
      type = Message::ContentType::APPLICATION_DATA \
        if @write_cipher.is_a?(Cryptograph::Aead)
      alert_record = Message::Record.new(
        type: type,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [message],
        cipher: @write_cipher
      )
      send_record(alert_record)
    end

    # @param record [TLS13::Message::Record]
    def send_record(record)
      @socket.write(record.serialize(@send_record_size))
    end

    # @raise [TLS13::Error::ErrorAlerts
    #
    # @return [TLS13::Message::$Object]
    # rubocop: disable Metrics/CyclomaticComplexity
    def recv_message
      return @message_queue.shift unless @message_queue.empty?

      messages = nil
      loop do
        record = recv_record
        case record.type
        when Message::ContentType::HANDSHAKE,
             Message::ContentType::APPLICATION_DATA
          messages = record.messages
          break unless messages.empty?
        when Message::ContentType::CCS
          terminate(:unexpected_message) unless ccs_receivable?
          next
        when Message::ContentType::ALERT
          handle_received_alert(record.messages.first)
          return nil
        else
          terminate(:unexpected_message)
        end
      end

      @message_queue += messages[1..]
      message = messages.first
      if message.is_a?(Message::Alert)
        handle_received_alert(message)
        return nil
      end

      message
    end
    # rubocop: enable Metrics/CyclomaticComplexity

    # @return [TLS13::Message::Record]
    def recv_record
      binary = @socket.read(5)
      record_len = Convert.bin2i(binary.slice(3, 2))
      binary += @socket.read(record_len)

      begin
        buffer = @binary_buffer
        record = Message::Record.deserialize(binary, @read_cipher, buffer)
        @binary_buffer = record.surplus_binary
      rescue Error::ErrorAlerts => e
        terminate(e.message.to_sym)
      end

      # Received a protected ccs, peer MUST abort the handshake.
      if record.type == Message::ContentType::APPLICATION_DATA &&
         record.messages.first.is_a?(Message::ChangeCipherSpec)
        terminate(:unexpected_message)
      end

      record
    end

    # @param digest [String] name of digest algorithm
    #
    # @return [String]
    def do_sign_psk_binder(digest)
      # TODO: ext binder
      secret = @key_schedule.binder_key_res
      hash_len = OpenSSL::Digest.new(digest).digest_length
      # transcript-hash (CH1 + HRR +) truncated-CH
      hash = @transcript.truncate_hash(digest, CH, hash_len + 3)
      OpenSSL::HMAC.digest(digest, secret, hash)
    end

    # @param certificate_pem [String]
    # @param signature_scheme [TLS13::SignatureScheme]
    # @param signature [String]
    # @param context [String]
    # @param handshake_context_end [Integer]
    #
    # @raise [TLS13::Error::ErrorAlerts]
    #
    # @return [Boolean]
    # rubocop: disable Metrics/CyclomaticComplexity
    def do_verify_certificate_verify(certificate_pem:, signature_scheme:,
                                     signature:, context:,
                                     handshake_context_end:)
      digest = CipherSuite.digest(@cipher_suite)
      hash = @transcript.hash(digest, handshake_context_end)
      content = "\x20" * 64 + context + "\x00" + hash
      public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key

      case signature_scheme
      when SignatureScheme::RSA_PSS_RSAE_SHA256,
           SignatureScheme::RSA_PSS_PSS_SHA256
        public_key.verify_pss('SHA256', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA256')
      when SignatureScheme::RSA_PSS_RSAE_SHA384,
           SignatureScheme::RSA_PSS_PSS_SHA384
        public_key.verify_pss('SHA384', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA384')
      when SignatureScheme::RSA_PSS_RSAE_SHA512,
           SignatureScheme::RSA_PSS_PSS_SHA512
        public_key.verify_pss('SHA512', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA512')
      when SignatureScheme::RSA_PKCS1_SHA256,
           SignatureScheme::ECDSA_SECP256R1_SHA256
        public_key.verify('SHA256', signature, content)
      when SignatureScheme::RSA_PKCS1_SHA384,
           SignatureScheme::ECDSA_SECP384R1_SHA384
        public_key.verify('SHA384', signature, content)
      when SignatureScheme::RSA_PKCS1_SHA512,
           SignatureScheme::ECDSA_SECP521R1_SHA512
        public_key.verify('SHA512', signature, content)
      else # TODO: ED25519, ED448
        terminate(:internal_error)
      end
    end
    # rubocop: enable Metrics/CyclomaticComplexity

    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param handshake_context_end [Integer]
    #
    # @return [String]
    def do_sign_finished(digest:, finished_key:, handshake_context_end:)
      hash = @transcript.hash(digest, handshake_context_end)
      OpenSSL::HMAC.digest(digest, finished_key, hash)
    end

    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param handshake_context_end [Integer]
    # @param signature [String]
    #
    # @return [Boolean]
    def do_verify_finished(digest:, finished_key:, handshake_context_end:,
                           signature:)
      do_sign_finished(
        digest: digest,
        finished_key: finished_key,
        handshake_context_end: handshake_context_end
      ) == signature
    end

    # @param key_exchange [String]
    # @param priv_key [OpenSSL::PKey::$Object]
    # @param group [TLS13::Message::ExtensionType::NamedGroup]
    #
    # @return [String]
    def gen_shared_secret(key_exchange, priv_key, group)
      curve = Message::Extension::NamedGroup.curve_name(group)
      terminate(:internal_error) if curve.nil?

      pub_key = OpenSSL::PKey::EC::Point.new(
        OpenSSL::PKey::EC::Group.new(curve),
        OpenSSL::BN.new(key_exchange, 2)
      )

      priv_key.dh_compute_key(pub_key)
    end

    # @return [Boolean]
    #
    # Received ccs before the first ClientHello message or after the peer's
    # Finished message, peer MUST abort.
    def ccs_receivable?
      return false unless @transcript.include?(CH)
      return false if @endpoint == :client && @transcript.include?(SF)
      return false if @endpoint == :server && @transcript.include?(CF)

      true
    end

    # @param symbol [Symbol] key of ALERT_DESCRIPTION
    #
    # @raise [TLS13::Error::ErrorAlerts]
    def terminate(symbol)
      send_alert(symbol)
      raise Error::ErrorAlerts, symbol
    end

    def handle_received_alert(alert)
      unless alert.description == Message::ALERT_DESCRIPTION[:close_notify] ||
             alert.description == Message::ALERT_DESCRIPTION[:user_canceled]
        raise alert.to_error
      end

      @state = EOF
    end

    # @param _nst [TLS13::Message::NewSessionTicket]
    #
    # @raise [TLS13::Error::ErrorAlerts]
    def process_new_session_ticket(_nst)
      terminate(:unexpected_message) if @endpoint == :server
    end

    # @param certificate_list [Array of CertificateEntry]
    # @param ca_file [String] path to ca.crt
    # @param hostname [String]
    #
    # @return [Boolean]
    # rubocop: disable Metrics/AbcSize
    def certified_certificate?(certificate_list, ca_file = nil, hostname = nil)
      store = OpenSSL::X509::Store.new
      store.set_default_paths
      store.add_file(ca_file) unless ca_file.nil?

      cert_bin = certificate_list.first.cert_data
      cert = OpenSSL::X509::Certificate.new(cert_bin)

      chain = certificate_list[1..].map(&:cert_data).map do |c|
        OpenSSL::X509::Certificate.new(c)
      end
      # TODO: parse authorityInfoAccess::CA Issuers

      ctx = OpenSSL::X509::StoreContext.new(store, cert, chain)

      # not support CN matching, only support SAN matching
      unless hostname.nil?
        san = cert.extensions.find { |ex| ex.oid == 'subjectAltName' }
        terminate(:bad_certificate) if san.nil?
        ostr = OpenSSL::ASN1.decode(san.to_der).value.last
        san_match = OpenSSL::ASN1.decode(ostr.value).map(&:value)
                                 .map { |s| s.gsub('.', '\.').gsub('*', '.*') }
                                 .any? { |s| hostname.match(/#{s}/) }
        return san_match && ctx.verify
      end
      ctx.verify
    end
    # rubocop: enable Metrics/AbcSize
  end
  # rubocop: enable Metrics/ClassLength
end
