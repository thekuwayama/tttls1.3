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
      @read_seq_num = nil # TLS13::SequenceNumber
      @write_cipher = Cryptograph::Passer.new
      @write_seq_num = nil # TLS13::SequenceNumber
      @transcript = Transcript.new
      @message_queue = [] # Array of TLS13::Message::$Object
      @binary_buffer = '' # deposit Record.surplus_binary
      @cipher_suite = nil # TLS13::CipherSuite
      @notyet_application_secret = true
      @state = 0 # ClientState or ServerState
      @send_record_size = Message::DEFAULT_RECORD_SIZE_LIMIT
    end

    # @raise [TLS13::Error::TLSError]
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

        process_new_session_ticket
      end
      return '' if message.nil?

      message.fragment
    end

    # @return [Boolean]
    def eof?
      @state == EOF
    end

    # @param binary [String]
    def write(binary)
      # secure channel has not established yet
      raise Error::ConfigError \
        unless @endpoint == :client && @state == ClientState::CONNECTED

      ap = Message::ApplicationData.new(binary)
      send_application_data(ap)
    end

    private

    # @param type [TLS13::Message::ContentType]
    # @param messages [Array of TLS13::Message::$Object] handshake messages
    def send_handshakes(type, messages)
      if @write_seq_num.nil? &&
         type == Message::ContentType::APPLICATION_DATA
        @write_seq_num = SequenceNumber.new
        @write_cipher \
        = gen_aead_with_handshake_traffic_secret(@write_seq_num, @endpoint)
      end
      record = Message::Record.new(type: type, messages: messages,
                                   cipher: @write_cipher)
      send_record(record)
      return if messages.none? { |m| m.is_a?(Message::Finished) }

      @write_seq_num = SequenceNumber.new
      @write_cipher \
      = gen_aead_with_application_traffic_secret(@write_seq_num, @endpoint)
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
    def send_application_data(message)
      ap_record = Message::Record.new(
        type: Message::ContentType::APPLICATION_DATA,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [message],
        cipher: @write_cipher
      )
      send_record(ap_record)
    end

    # @param symbol [Symbol] key of ALERT_DESCRIPTION
    def send_alert(symbol)
      message = Message::Alert.new(
        description: Message::ALERT_DESCRIPTION[symbol]
      )
      alert_record = Message::Record.new(
        type: Message::ContentType::ALERT,
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

    # @raise [TLS13::Error::TLSError
    #
    # @return [TLS13::Message::$Object]
    # rubocop: disable Metrics/CyclomaticComplexity
    # rubocop: disable Metrics/MethodLength
    # rubocop: disable Metrics/PerceivedComplexity
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
          alert = record.messages.first
          if alert.description == Message::ALERT_DESCRIPTION[:close_notify]
            @state = EOF
            return nil
          end
          raise alert.to_error
        else
          terminate(:unexpected_message)
        end
      end

      @message_queue += messages[1..]
      message = messages.first
      if message.is_a?(Message::Alert) &&
         message.description == Message::ALERT_DESCRIPTION[:close_notify]
        @state = EOF
        return nil
      elsif message.is_a?(Message::Alert)
        raise message.to_error
      end

      message
    end
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/MethodLength
    # rubocop: enable Metrics/PerceivedComplexity

    # @return [TLS13::Message::Record]
    # rubocop: disable Metrics/CyclomaticComplexity
    # rubocop: disable Metrics/PerceivedComplexity
    def recv_record
      binary = @socket.read(5)
      record_len = Convert.bin2i(binary.slice(3, 2))
      binary += @socket.read(record_len)

      if @read_seq_num.nil? &&
         binary[0] == Message::ContentType::APPLICATION_DATA
        @read_seq_num = SequenceNumber.new
        sender = (@endpoint == :client ? :server : :client)
        @read_cipher \
        = gen_aead_with_handshake_traffic_secret(@read_seq_num, sender)
      elsif @transcript.key?(SF) && @notyet_application_secret
        @read_seq_num = SequenceNumber.new
        sender = (@endpoint == :client ? :server : :client)
        @read_cipher \
        = gen_aead_with_application_traffic_secret(@read_seq_num, sender)
        @notyet_application_secret = false
      end

      begin
        buffer = @binary_buffer
        record = Message::Record.deserialize(binary, @read_cipher, buffer)
        @binary_buffer = record.surplus_binary
      rescue Error::TLSError => e
        terminate(e.message)
      end

      # Received a protected ccs, peer MUST abort the handshake.
      if record.type == Message::ContentType::APPLICATION_DATA &&
         record.messages.first.is_a?(Message::ChangeCipherSpec)
        terminate(:unexpected_message)
      end

      record
    end
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/PerceivedComplexity

    # @param certificate_pem [String]
    # @param signature_scheme [TLS13::SignatureScheme]
    # @param signature [String]
    # @param context [String]
    # @param message_range [Range]
    #
    # @raise [RuntimeError]
    #
    # @return [Boolean]
    def do_verify_certificate_verify(certificate_pem:, signature_scheme:,
                                     signature:, context:, message_range:)
      digest = CipherSuite.digest(@cipher_suite)
      hash = @transcript.hash(digest, message_range)
      case signature_scheme
      when SignatureScheme::RSA_PKCS1_SHA256,
           SignatureScheme::ECDSA_SECP256R1_SHA256,
           SignatureScheme::RSA_PSS_RSAE_SHA256,
           SignatureScheme::RSA_PSS_PSS_SHA256
        content = "\x20" * 64 + context + "\x00" + hash
        public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
        public_key.verify_pss('SHA256', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA256')
      when SignatureScheme::RSA_PKCS1_SHA384,
           SignatureScheme::ECDSA_SECP384R1_SHA384,
           SignatureScheme::RSA_PSS_RSAE_SHA384,
           SignatureScheme::RSA_PSS_PSS_SHA384
        content = "\x20" * 64 + context + "\x00" + hash
        public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
        public_key.verify_pss('SHA384', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA384')
      when SignatureScheme::RSA_PKCS1_SHA512,
           SignatureScheme::ECDSA_SECP521R1_SHA512,
           SignatureScheme::RSA_PSS_RSAE_SHA512,
           SignatureScheme::RSA_PSS_PSS_SHA512
        content = "\x20" * 64 + context + "\x00" + hash
        public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
        public_key.verify_pss('SHA512', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA512')
      else # TODO: ED25519, ED448
        terminate(:internal_error)
      end
    end

    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param message_range [Range]
    #
    # @return [String]
    def do_sign_finished(digest:, finished_key:, message_range:)
      hash = @transcript.hash(digest, message_range)
      OpenSSL::HMAC.digest(digest, finished_key, hash)
    end

    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param message_range [Range]
    # @param signature [String]
    #
    # @return [Boolean]
    def do_verify_finished(digest:, finished_key:, message_range:, signature:)
      do_sign_finished(digest: digest,
                       finished_key: finished_key,
                       message_range: message_range) == signature
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

    # @param seq_num [TLS13::SequenceNumber]
    # @param sender [Symbol, :client or :server]
    #
    # @return [TLS13::Cryptograph::Aead]
    def gen_aead_with_handshake_traffic_secret(seq_num, sender)
      write_key = @key_schedule.send("#{sender}_handshake_write_key")
      write_iv = @key_schedule.send("#{sender}_handshake_write_iv")

      Cryptograph::Aead.new(
        cipher_suite: @cipher_suite,
        write_key: write_key,
        write_iv: write_iv,
        sequence_number: seq_num
      )
    end

    # @param seq_num [TLS13::SequenceNumber]
    # @param sender [Symbol, :client or :server]
    #
    # @return [TLS13::Cryptograph::Aead]
    def gen_aead_with_application_traffic_secret(seq_num, sender)
      write_key = @key_schedule.send("#{sender}_application_write_key")
      write_iv = @key_schedule.send("#{sender}_application_write_iv")

      Cryptograph::Aead.new(
        cipher_suite: @cipher_suite,
        write_key: write_key,
        write_iv: write_iv,
        sequence_number: seq_num
      )
    end

    # @return [Boolean]
    #
    # Received ccs before the first ClientHello message or after the peer's
    # Finished message, peer MUST abort.
    def ccs_receivable?
      return false unless @transcript.key?(CH)
      return false if @endpoint == :client && @transcript.key?(SF)
      return false if @endpoint == :server && @transcript.key?(CF)

      true
    end

    # @param symbol [Symbol] key of ALERT_DESCRIPTION
    #
    # @raise [TLS13::Error::TLSError]
    def terminate(symbol)
      send_alert(symbol)
      raise Error::TLSError, symbol
    end

    # @raise [TLS13::Error::TLSError]
    def process_new_session_ticket
      terminate(:unexpected_message) if @endpoint == :server
      # TODO: @endpoint == :client
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
