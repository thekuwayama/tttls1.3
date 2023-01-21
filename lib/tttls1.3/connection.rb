# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  INITIAL = 0
  EOF     = -1

  # rubocop: disable Metrics/ClassLength
  class Connection
    include Logging

    # @param socket [Socket]
    def initialize(socket)
      @socket = socket
      @endpoint = nil # Symbol or String, :client or :server
      @ap_wcipher = Cryptograph::Passer.new
      @ap_rcipher = Cryptograph::Passer.new
      @alert_wcipher = Cryptograph::Passer.new
      @message_queue = [] # Array of [TTTLS13::Message::$Object, String]
      @binary_buffer = '' # deposit Record.surplus_binary
      @cipher_suite = nil # TTTLS13::CipherSuite
      @named_group = nil # TTTLS13::NamedGroup
      @signature_scheme = nil # TTTLS13::SignatureScheme
      @state = 0 # ClientState or ServerState
      @send_record_size = Message::DEFAULT_RECORD_SIZE_LIMIT
      @recv_record_size = Message::DEFAULT_RECORD_SIZE_LIMIT
      @alpn = nil # String
      @exporter_secret = nil # String
    end

    # @raise [TTTLS13::Error::ConfigError]
    #
    # @return [String]
    # rubocop: disable Metrics/CyclomaticComplexity
    # rubocop: disable Metrics/PerceivedComplexity
    def read
      # secure channel has not established yet
      raise Error::ConfigError \
        unless (@endpoint == :client && @state == ClientState::CONNECTED) ||
               (@endpoint == :server && @state == ServerState::CONNECTED)
      return '' if @state == EOF

      message = nil
      loop do
        message, = recv_message(receivable_ccs: false, cipher: @ap_rcipher)
        # At any time after the server has received the client Finished
        # message, it MAY send a NewSessionTicket message.
        break unless message.is_a?(Message::NewSessionTicket)

        process_new_session_ticket(message)
      end
      return '' if message.nil?

      message.fragment
    end
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Metrics/PerceivedComplexity

    # @return [Boolean]
    def eof?
      @state == EOF
    end

    # @param binary [String]
    #
    # @raise [TTTLS13::Error::ConfigError]
    def write(binary)
      # secure channel has not established yet
      raise Error::ConfigError \
        unless (@endpoint == :client && @state == ClientState::CONNECTED) ||
               (@endpoint == :server && @state == ServerState::CONNECTED)

      ap = Message::ApplicationData.new(binary)
      send_application_data(ap, @ap_wcipher)
    end

    def close
      return if @state == EOF

      send_alert(:close_notify)
      @state = EOF

      nil
    end

    # @return [TTTLS13::CipherSuite, nil]
    def negotiated_cipher_suite
      @cipher_suite
    end

    # @return [TTTLS13::NamedGroup, nil]
    def negotiated_named_group
      @named_group
    end

    # @return [TTTLS13::SignatureScheme, nil]
    def negotiated_signature_scheme
      @signature_scheme
    end

    # @return [String]
    def negotiated_alpn
      @alpn
    end

    # @param label [String]
    # @param context [String]
    # @param key_length [Integer]
    #
    # @return [String, nil]
    def exporter(label, context, key_length)
      return nil if @exporter_secret.nil? || @cipher_suite.nil?

      digest = CipherSuite.digest(@cipher_suite)
      do_exporter(@exporter_secret, digest, label, context, key_length)
    end

    private

    # @param secret [String] (early_)exporter_secret
    # @param digest [String] name of digest algorithm
    # @param label [String]
    # @param context [String]
    # @param key_length [Integer]
    #
    # @return [String]
    def do_exporter(secret, digest, label, context, key_length)
      derived_secret = KeySchedule.hkdf_expand_label(
        secret,
        label,
        OpenSSL::Digest.digest(digest, ''),
        OpenSSL::Digest.new(digest).digest_length,
        digest
      )

      KeySchedule.hkdf_expand_label(
        derived_secret,
        'exporter',
        OpenSSL::Digest.digest(digest, context),
        key_length,
        digest
      )
    end

    # @param cipher_suite [TTTLS13::CipherSuite]
    # @param write_key [String]
    # @param write_iv [String]
    #
    # @return [TTTLS13::Cryptograph::Aead]
    def gen_cipher(cipher_suite, write_key, write_iv)
      seq_num = SequenceNumber.new
      Cryptograph::Aead.new(
        cipher_suite: cipher_suite,
        write_key: write_key,
        write_iv: write_iv,
        sequence_number: seq_num
      )
    end

    # @param type [TTTLS13::Message::ContentType]
    # @param messages [Array of TTTLS13::Message::$Object] handshake messages
    # @param cipher [TTTLS13::Cryptograph::Aead, Passer]
    def send_handshakes(type, messages, cipher)
      record = Message::Record.new(
        type: type,
        messages: messages,
        cipher: cipher
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

    # @param message [TTTLS13::Message::ApplicationData]
    # @param cipher [TTTLS13::Cryptograph::Aead]
    def send_application_data(message, cipher)
      ap_record = Message::Record.new(
        type: Message::ContentType::APPLICATION_DATA,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [message],
        cipher: cipher
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
        if @alert_wcipher.is_a?(Cryptograph::Aead)
      alert_record = Message::Record.new(
        type: type,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [message],
        cipher: @alert_wcipher
      )
      send_record(alert_record)
    end

    # @param record [TTTLS13::Message::Record]
    def send_record(record)
      logger.debug("send \n" + record.pretty_inspect)
      @socket.write(record.serialize(@send_record_size))
    end

    # @param receivable_ccs [Boolean]
    # @param cipher [TTTLS13::Cryptograph::Aead, Passer]
    #
    # @raise [TTTLS13::Error::ErrorAlerts
    #
    # @return [TTTLS13::Message::$Object]
    # @return [String]
    # rubocop: disable Metrics/CyclomaticComplexity
    def recv_message(receivable_ccs:, cipher:)
      return @message_queue.shift unless @message_queue.empty?

      messages = nil
      orig_msgs = []
      loop do
        record, orig_msgs = recv_record(cipher)
        case record.type
        when Message::ContentType::HANDSHAKE,
             Message::ContentType::APPLICATION_DATA
          messages = record.messages
          break unless messages.empty?
        when Message::ContentType::CCS
          terminate(:unexpected_message) unless receivable_ccs
          next
        when Message::ContentType::ALERT
          handle_received_alert(record.messages.first)
          return nil
        else
          terminate(:unexpected_message)
        end
      end

      @message_queue += messages[1..].zip(orig_msgs[1..])
      message = messages.first
      orig_msg = orig_msgs.first
      if message.is_a?(Message::Alert)
        handle_received_alert(message)
        return nil
      end

      [message, orig_msg]
    end
    # rubocop: enable Metrics/CyclomaticComplexity

    # @param cipher [TTTLS13::Cryptograph::Aead, Passer]
    #
    # @return [TTTLS13::Message::Record]
    # @return [Array of String]
    def recv_record(cipher)
      binary = @socket.read(5)
      record_len = Convert.bin2i(binary.slice(3, 2))
      binary += @socket.read(record_len)

      begin
        buffer = @binary_buffer
        record, orig_msgs, surplus_binary = Message::Record.deserialize(
          binary,
          cipher,
          buffer,
          @recv_record_size
        )
        @binary_buffer = surplus_binary
      rescue Error::ErrorAlerts => e
        terminate(e.message.to_sym)
      end

      # Received a protected ccs, peer MUST abort the handshake.
      if record.type == Message::ContentType::APPLICATION_DATA &&
         record.messages.any? { |m| m.is_a?(Message::ChangeCipherSpec) }
        terminate(:unexpected_message)
      end

      logger.debug("receive \n" + record.pretty_inspect)
      [record, orig_msgs]
    end

    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    # @param ch [TTTLS13::Message::ClientHello]
    # @param binder_key [String]
    # @param digest [String] name of digest algorithm
    #
    # @return [String]
    def do_sign_psk_binder(ch1:, hrr:, ch:, binder_key:, digest:)
      # TODO: ext binder
      hash_len = OpenSSL::Digest.new(digest).digest_length
      tt = Transcript.new
      tt[CH1] = [ch1, ch1.serialize] unless ch1.nil?
      tt[HRR] = [hrr, hrr.serialize] unless hrr.nil?
      tt[CH] = [ch, ch.serialize]
      # transcript-hash (CH1 + HRR +) truncated-CH
      hash = tt.truncate_hash(digest, CH, hash_len + 3)
      OpenSSL::HMAC.digest(digest, binder_key, hash)
    end

    # @param key [OpenSSL::PKey::PKey]
    # @param signature_scheme [TTTLS13::SignatureScheme]
    # @param context [String]
    # @param hash [String]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [String]
    # rubocop: disable Metrics/CyclomaticComplexity
    def do_sign_certificate_verify(key:, signature_scheme:, context:, hash:)
      content = "\x20" * 64 + context + "\x00" + hash

      # RSA signatures MUST use an RSASSA-PSS algorithm, regardless of whether
      # RSASSA-PKCS1-v1_5 algorithms appear in "signature_algorithms".
      case signature_scheme
      when SignatureScheme::RSA_PKCS1_SHA256,
           SignatureScheme::RSA_PSS_RSAE_SHA256,
           SignatureScheme::RSA_PSS_PSS_SHA256
        key.sign_pss('SHA256', content, salt_length: :digest,
                                        mgf1_hash: 'SHA256')
      when SignatureScheme::RSA_PKCS1_SHA384,
           SignatureScheme::RSA_PSS_RSAE_SHA384,
           SignatureScheme::RSA_PSS_PSS_SHA384
        key.sign_pss('SHA384', content, salt_length: :digest,
                                        mgf1_hash: 'SHA384')
      when SignatureScheme::RSA_PKCS1_SHA512,
           SignatureScheme::RSA_PSS_RSAE_SHA512,
           SignatureScheme::RSA_PSS_PSS_SHA512
        key.sign_pss('SHA512', content, salt_length: :digest,
                                        mgf1_hash: 'SHA512')
      when SignatureScheme::ECDSA_SECP256R1_SHA256
        key.sign('SHA256', content)
      when SignatureScheme::ECDSA_SECP384R1_SHA384
        key.sign('SHA384', content)
      when SignatureScheme::ECDSA_SECP521R1_SHA512
        key.sign('SHA512', content)
      else # TODO: ED25519, ED448
        terminate(:internal_error)
      end
    end
    # rubocop: enable Metrics/CyclomaticComplexity

    # @param public_key [OpenSSL::PKey::PKey]
    # @param signature_scheme [TTTLS13::SignatureScheme]
    # @param signature [String]
    # @param context [String]
    # @param hash [String]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [Boolean]
    # rubocop: disable Metrics/CyclomaticComplexity
    def do_verified_certificate_verify?(public_key:, signature_scheme:,
                                        signature:, context:, hash:)
      content = "\x20" * 64 + context + "\x00" + hash

      # RSA signatures MUST use an RSASSA-PSS algorithm, regardless of whether
      # RSASSA-PKCS1-v1_5 algorithms appear in "signature_algorithms".
      case signature_scheme
      when SignatureScheme::RSA_PKCS1_SHA256,
           SignatureScheme::RSA_PSS_RSAE_SHA256,
           SignatureScheme::RSA_PSS_PSS_SHA256
        public_key.verify_pss('SHA256', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA256')
      when SignatureScheme::RSA_PKCS1_SHA384,
           SignatureScheme::RSA_PSS_RSAE_SHA384,
           SignatureScheme::RSA_PSS_PSS_SHA384
        public_key.verify_pss('SHA384', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA384')
      when SignatureScheme::RSA_PKCS1_SHA512,
           SignatureScheme::RSA_PSS_RSAE_SHA512,
           SignatureScheme::RSA_PSS_PSS_SHA512
        public_key.verify_pss('SHA512', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA512')
      when SignatureScheme::ECDSA_SECP256R1_SHA256
        public_key.verify('SHA256', signature, content)
      when SignatureScheme::ECDSA_SECP384R1_SHA384
        public_key.verify('SHA384', signature, content)
      when SignatureScheme::ECDSA_SECP521R1_SHA512
        public_key.verify('SHA512', signature, content)
      else # TODO: ED25519, ED448
        terminate(:internal_error)
      end
    end
    # rubocop: enable Metrics/CyclomaticComplexity

    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param hash [String]
    #
    # @return [String]
    def sign_finished(digest:, finished_key:, hash:)
      OpenSSL::HMAC.digest(digest, finished_key, hash)
    end

    # @param finished [TTTLS13::Message::Finished]
    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param hash [String]
    #
    # @return [Boolean]
    def verified_finished?(finished:, digest:, finished_key:, hash:)
      sign_finished(digest: digest, finished_key: finished_key, hash: hash) \
      == finished.verify_data
    end

    # @param key_exchange [String]
    # @param priv_key [OpenSSL::PKey::$Object]
    # @param group [TTTLS13::NamedGroup]
    #
    # @return [String]
    def gen_shared_secret(key_exchange, priv_key, group)
      curve = NamedGroup.curve_name(group)
      terminate(:internal_error) if curve.nil?

      pub_key = OpenSSL::PKey::EC::Point.new(
        OpenSSL::PKey::EC::Group.new(curve),
        OpenSSL::BN.new(key_exchange, 2)
      )

      priv_key.dh_compute_key(pub_key)
    end

    # @param transcript [TTTLS13::Transcript]
    #
    # @return [Boolean]
    def receivable_ccs?(transcript)
      # Received ccs before the first ClientHello message or after the peer's
      # Finished message, peer MUST abort.
      #
      # Server may receive an unprotected record of type change_cipher_spec
      # between the first and second ClientHello
      finished = (@endpoint == :client ? SF : CF)

      (transcript.include?(CH) || transcript.include?(CH1)) &&
        !transcript.include?(finished)
    end

    # @param symbol [Symbol] key of ALERT_DESCRIPTION
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    def terminate(symbol)
      send_alert(symbol)
      raise Error::ErrorAlerts, symbol
    end

    # @param alert [TTTLS13::Message::Alert]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    def handle_received_alert(alert)
      unless alert.description == Message::ALERT_DESCRIPTION[:close_notify] ||
             alert.description == Message::ALERT_DESCRIPTION[:user_canceled]
        raise alert.to_error
      end

      @state = EOF
      nil
    end

    # @param _nst [TTTLS13::Message::NewSessionTicket]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    def process_new_session_ticket(_nst)
      terminate(:unexpected_message) if @endpoint == :server
    end

    # @param certificate_list [Array of CertificateEntry]
    # @param ca_file [String] path to ca.crt
    # @param hostname [String]
    #
    # @return [Boolean]
    def trusted_certificate?(certificate_list, ca_file = nil, hostname = nil)
      chain = certificate_list.map(&:cert_data).map do |c|
        OpenSSL::X509::Certificate.new(c)
      end
      cert = chain.shift

      # not support CN matching, only support SAN matching
      return false if !hostname.nil? && !matching_san?(cert, hostname)

      store = OpenSSL::X509::Store.new
      store.set_default_paths
      store.add_file(ca_file) unless ca_file.nil?
      # TODO: parse authorityInfoAccess::CA Issuers
      ctx = OpenSSL::X509::StoreContext.new(store, cert, chain)
      now = Time.now
      ctx.verify && cert.not_before < now && now < cert.not_after
    end

    # @param cert [OpenSSL::X509::Certificate]
    # @param name [String]
    #
    # @return [Boolean]
    def matching_san?(cert, name)
      san = cert.extensions.find { |ex| ex.oid == 'subjectAltName' }
      return false if san.nil?

      ostr = OpenSSL::ASN1.decode(san.to_der).value.last
      OpenSSL::ASN1.decode(ostr.value)
                   .map(&:value)
                   .map { |s| s.gsub('.', '\.').gsub('*', '.*') }
                   .any? { |s| name.match(/#{s}/) }
    end

    # @param signature_algorithms [Array of SignatureAlgorithms]
    # @param crt [OpenSSL::X509::Certificate]
    #
    # @return [Array of TTTLS13::Message::Extension::SignatureAlgorithms]
    def do_select_signature_algorithms(signature_algorithms, crt)
      pka = OpenSSL::ASN1.decode(crt.public_key.to_der)
                         .value.first.value.first.value
      signature_algorithms.select do |sa|
        case sa
        when SignatureScheme::ECDSA_SECP256R1_SHA256,
             SignatureScheme::ECDSA_SECP384R1_SHA384,
             SignatureScheme::ECDSA_SECP521R1_SHA512
          pka == 'id-ecPublicKey'
        when SignatureScheme::RSA_PSS_PSS_SHA256,
             SignatureScheme::RSA_PSS_PSS_SHA384,
             SignatureScheme::RSA_PSS_PSS_SHA512
          pka == 'rsassaPss'
        when SignatureScheme::RSA_PSS_RSAE_SHA256,
             SignatureScheme::RSA_PSS_RSAE_SHA384,
             SignatureScheme::RSA_PSS_RSAE_SHA512
          pka == 'rsaEncryption'
        else
          # RSASSA-PKCS1-v1_5 algorithms refer solely to signatures which appear
          # in certificates and are not defined for use in signed TLS handshake
          # messages
          false
        end
      end
    end

    class << self
      # @param cid [OpenSSL::OCSP::CertificateId]
      #
      # @return [OpenSSL::OCSP::Request]
      def gen_ocsp_request(cid)
        ocsp_request = OpenSSL::OCSP::Request.new
        ocsp_request.add_certid(cid)
        ocsp_request.add_nonce
        ocsp_request
      end

      # @param ocsp_request [OpenSSL::OCSP::Request]
      # @param uri_string [String]
      #
      # @raise [Net::OpenTimeout, OpenSSL::OCSP::OCSPError, URI::$Exception]
      #
      # @return [OpenSSL::OCSP::Response, n
      def send_ocsp_request(ocsp_request, uri_string)
        # send HTTP POST
        uri = URI.parse(uri_string)
        path = uri.path
        path = '/' if path.nil? || path.empty?
        http_response = Net::HTTP.start(uri.host, uri.port) do |http|
          http.post(
            path,
            ocsp_request.to_der,
            'content-type' => 'application/ocsp-request'
          )
        end

        OpenSSL::OCSP::Response.new(http_response.body)
      end
    end
  end
  # rubocop: enable Metrics/ClassLength
end
