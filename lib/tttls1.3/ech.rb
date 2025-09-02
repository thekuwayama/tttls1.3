# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements

  SUPPORTED_ECHCONFIG_VERSIONS = ["\xfe\x0d"].freeze
  private_constant :SUPPORTED_ECHCONFIG_VERSIONS

  DEFAULT_ECH_OUTER_EXTENSIONS = [
    Message::ExtensionType::KEY_SHARE
  ].freeze
  private_constant :DEFAULT_ECH_OUTER_EXTENSIONS

  # rubocop: disable Metrics/ClassLength
  class Ech
    # @param inner [TTTLS13::Message::ClientHello]
    # @param ech_config [ECHConfig]
    # @param hpke_cipher_suite_selector [Method]
    #
    # @return [TTTLS13::Message::ClientHello]
    # @return [TTTLS13::Message::ClientHello] ClientHelloInner
    # @return [TTTLS13::EchState]
    # rubocop: disable Metrics/AbcSize
    def self.offer_ech(inner, ech_config, hpke_cipher_suite_selector)
      return [new_greased_ch(inner, new_grease_ech), nil, nil] \
        if ech_config.nil? ||
           !SUPPORTED_ECHCONFIG_VERSIONS.include?(ech_config.version)

      # Encrypted ClientHello Configuration
      ech_state, enc = encrypted_ech_config(
        ech_config,
        hpke_cipher_suite_selector
      )
      return [new_greased_ch(inner, new_grease_ech), nil, nil] \
        if ech_state.nil? || enc.nil?

      # for ech_outer_extensions
      replaced = \
        inner.extensions.remove_and_replace!(DEFAULT_ECH_OUTER_EXTENSIONS)

      # Encoding the ClientHelloInner
      encoded = encode_ch_inner(inner, ech_state.maximum_name_length, replaced)
      overhead_len = aead_id2overhead_len(ech_state.cipher_suite.aead_id.uint16)

      # Authenticating the ClientHelloOuter
      aad = new_ch_outer_aad(
        inner,
        ech_state.cipher_suite,
        ech_state.config_id,
        enc,
        encoded.length + overhead_len,
        ech_state.public_name
      )

      outer = new_ch_outer(
        aad,
        ech_state.cipher_suite,
        ech_state.config_id,
        enc,
        # which does not include the Handshake structure's four byte header.
        ech_state.ctx.seal(aad.serialize[4..], encoded)
      )

      [outer, inner, ech_state]
    end
    # rubocop: enable Metrics/AbcSize

    # @param ech_config [ECHConfig]
    # @param hpke_cipher_suite_selector [Method]
    #
    # @return [TTTLS13::EchState or nil]
    # @return [String or nil]
    # rubocop: disable Metrics/AbcSize
    def self.encrypted_ech_config(ech_config, hpke_cipher_suite_selector)
      public_name = ech_config.echconfig_contents.public_name
      key_config = ech_config.echconfig_contents.key_config
      public_key = key_config.public_key.opaque
      kem_id = key_config&.kem_id&.uint16
      config_id = key_config.config_id
      cipher_suite = hpke_cipher_suite_selector.call(key_config)
      aead_cipher = cipher_suite&.aead_id&.uint16
      return [nil, nil] \
        if [kem_id, aead_cipher].any?(&:nil?)

      kem_curve, hash = kem_id2dhkem(kem_id)
      pkr = kem_curve&.new(hash)&.deserialize_public_key(public_key)
      return [nil, nil] if pkr.nil?

      hpke = HPKE.new(kem_id, hash, aead_cipher)
      base_s = hpke.setup_base_s(pkr, "tls ech\x00" + ech_config.encode)
      enc = base_s[:enc]
      ctx = base_s[:context_s]
      mnl = ech_config.echconfig_contents.maximum_name_length
      ech_state = EchState.new(
        mnl,
        config_id,
        cipher_suite,
        public_name,
        ctx
      )

      [ech_state, enc]
    end
    # rubocop: enable Metrics/AbcSize

    # @param inner [TTTLS13::Message::ClientHello]
    # @param ech_state [TTTLS13::EchState]
    #
    # @return [TTTLS13::Message::ClientHello]
    # @return [TTTLS13::Message::ClientHello] ClientHelloInner
    def self.offer_new_ech(inner, ech_state)
      # for ech_outer_extensions
      replaced = \
        inner.extensions.remove_and_replace!(DEFAULT_ECH_OUTER_EXTENSIONS)

      # Encoding the ClientHelloInner
      encoded = encode_ch_inner(inner, ech_state.maximum_name_length, replaced)
      overhead_len = \
        aead_id2overhead_len(ech_state.cipher_suite.aead_id.uint16)

      # It encrypts EncodedClientHelloInner as described in Section 6.1.1, using
      # the second partial ClientHelloOuterAAD, to obtain a second
      # ClientHelloOuter. It reuses the original HPKE encryption context
      # computed in Section 6.1 and uses the empty string for enc.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-6.1.5-4.4.1
      aad = new_ch_outer_aad(
        inner,
        ech_state.cipher_suite,
        ech_state.config_id,
        '',
        encoded.length + overhead_len,
        ech_state.public_name
      )

      # Authenticating the ClientHelloOuter
      outer = new_ch_outer(
        aad,
        ech_state.cipher_suite,
        ech_state.config_id,
        '',
        # which does not include the Handshake structure's four byte header.
        ech_state.ctx.seal(aad.serialize[4..], encoded)
      )

      [outer, inner]
    end

    # @param inner [TTTLS13::Message::ClientHello]
    # @param maximum_name_length [Integer]
    # @param replaced [TTTLS13::Message::Extensions]
    #
    # @return [String] EncodedClientHelloInner
    def self.encode_ch_inner(inner, maximum_name_length, replaced)
      encoded = Message::ClientHello.new(
        legacy_version: inner.legacy_version,
        random: inner.random,
        legacy_session_id: '',
        cipher_suites: inner.cipher_suites,
        legacy_compression_methods: inner.legacy_compression_methods,
        extensions: replaced
      )
      server_name_length = \
        replaced[Message::ExtensionType::SERVER_NAME].server_name.length

      padding_encoded_ch_inner(
        # which does not include the Handshake structure's four byte header.
        encoded.serialize[4..],
        server_name_length,
        maximum_name_length
      )
    end

    # @param s [String]
    # @param server_name_length [Integer]
    # @param maximum_name_length [Integer]
    #
    # @return [String]
    def self.padding_encoded_ch_inner(s,
                                      server_name_length,
                                      maximum_name_length)
      padding_len =
        if server_name_length.positive?
          [maximum_name_length - server_name_length, 0].max
        else
          9 + maximum_name_length
        end

      padding_len = 31 - ((s.length + padding_len - 1) % 32)
      s + padding_len.zeros
    end

    # @param inner [TTTLS13::Message::ClientHello]
    # @param cipher_suite [HpkeSymmetricCipherSuite]
    # @param config_id [Integer]
    # @param enc [String]
    # @param payload_len [Integer]
    # @param server_name [String]
    #
    # @return [TTTLS13::Message::ClientHello]
    # rubocop: disable Metrics/ParameterLists
    def self.new_ch_outer_aad(inner,
                              cipher_suite,
                              config_id,
                              enc,
                              payload_len,
                              server_name)
      aad_ech = Message::Extension::ECHClientHello.new_outer(
        cipher_suite:,
        config_id:,
        enc:,
        payload: payload_len.zeros
      )
      Message::ClientHello.new(
        legacy_version: inner.legacy_version,
        legacy_session_id: inner.legacy_session_id,
        cipher_suites: inner.cipher_suites,
        legacy_compression_methods: inner.legacy_compression_methods,
        extensions: inner.extensions.merge(
          Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => aad_ech,
          Message::ExtensionType::SERVER_NAME => \
            Message::Extension::ServerName.new(server_name)
        )
      )
    end
    # rubocop: enable Metrics/ParameterLists

    # @param aad [TTTLS13::Message::ClientHello]
    # @param cipher_suite [HpkeSymmetricCipherSuite]
    # @param config_id [Integer]
    # @param enc [String]
    # @param payload [String]
    #
    # @return [TTTLS13::Message::ClientHello]
    def self.new_ch_outer(aad, cipher_suite, config_id, enc, payload)
      outer_ech = Message::Extension::ECHClientHello.new_outer(
        cipher_suite:,
        config_id:,
        enc:,
        payload:
      )
      Message::ClientHello.new(
        legacy_version: aad.legacy_version,
        random: aad.random,
        legacy_session_id: aad.legacy_session_id,
        cipher_suites: aad.cipher_suites,
        legacy_compression_methods: aad.legacy_compression_methods,
        extensions: aad.extensions.merge(
          Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => outer_ech
        )
      )
    end

    # @return [Message::Extension::ECHClientHello]
    def self.new_grease_ech
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#name-compliance-requirements
      cipher_suite = HpkeSymmetricCipherSuite.new(
        HpkeSymmetricCipherSuite::HpkeKdfId.new(
          HPKE::HKDF_SHA256
        ),
        HpkeSymmetricCipherSuite::HpkeAeadId.new(
          HPKE::AES_128_GCM
        )
      )
      # Set the enc field to a randomly-generated valid encapsulated public key
      # output by the HPKE KEM.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-6.2-2.3.1
      public_key = OpenSSL::PKey.read(
        OpenSSL::PKey.generate_key('X25519').public_to_pem
      )
      hpke = HPKE.new(HPKE::DHKEM_X25519_HKDF_SHA256, HPKE::HKDF_SHA256, HPKE::AES_128_GCM)
      enc = hpke.setup_base_s(public_key, '')[:enc]
      # Set the payload field to a randomly-generated string of L+C bytes, where
      # C is the ciphertext expansion of the selected AEAD scheme and L is the
      # size of the EncodedClientHelloInner the client would compute when
      # offering ECH, padded according to Section 6.1.3.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-6.2-2.4.1
      payload_len = placeholder_encoded_ch_inner_len \
                    + aead_id2overhead_len(HPKE::AES_128_GCM)

      Message::Extension::ECHClientHello.new_outer(
        cipher_suite:,
        config_id: Convert.bin2i(OpenSSL::Random.random_bytes(1)),
        enc:,
        payload: OpenSSL::Random.random_bytes(payload_len)
      )
    end

    # @return [Integer]
    def self.placeholder_encoded_ch_inner_len
      480
    end

    # @param inner [TTTLS13::Message::ClientHello]
    # @param ech [Message::Extension::ECHClientHello]
    #
    # @return [TTTLS13::Message::ClientHello]
    def self.new_greased_ch(inner, ech)
      Message::ClientHello.new(
        legacy_version: inner.legacy_version,
        random: inner.random,
        legacy_session_id: inner.legacy_session_id,
        cipher_suites: inner.cipher_suites,
        legacy_compression_methods: inner.legacy_compression_methods,
        extensions: inner.extensions.merge(
          Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => ech
        )
      )
    end

    def self.kem_id2dhkem(kem_id)
      case kem_id
      when HPKE::DHKEM_P256_HKDF_SHA256
        [HPKE::DHKEM::EC::P_256, HPKE::HKDF_SHA256]
      when HPKE::DHKEM_P384_HKDF_SHA384
        [HPKE::DHKEM::EC::P_384, HPKE::HKDF_SHA384]
      when HPKE::DHKEM_P521_HKDF_SHA512
        [HPKE::DHKEM::EC::P_521, HPKE::HKDF_SHA512]
      when HPKE::DHKEM_X25519_HKDF_SHA256
        [HPKE::DHKEM::X25519, HPKE::HKDF_SHA256]
      when HPKE::DHKEM_X448_HKDF_SHA512
        [HPKE::DHKEM::X448, HPKE::HKDF_SHA512]
      end
    end

    def self.aead_id2overhead_len(aead_id)
      case aead_id
      when HPKE::AES_128_GCM, HPKE::CHACHA20_POLY1305
        16
      when HPKE::AES_256_GCM
        32
      end
    end
  end

  class EchState
    attr_reader :maximum_name_length, :config_id, :cipher_suite, :public_name, :ctx

    # @param maximum_name_length [Integer]
    # @param config_id [Integer]
    # @param cipher_suite [HpkeSymmetricCipherSuite]
    # @param public_name [String]
    # @param ctx [HPKE::ContextS]
    def initialize(maximum_name_length,
                   config_id,
                   cipher_suite,
                   public_name,
                   ctx)
      @maximum_name_length = maximum_name_length
      @config_id = config_id
      @cipher_suite = cipher_suite
      @public_name = public_name
      @ctx = ctx
    end
  end
  # rubocop: enable Metrics/ClassLength
end
