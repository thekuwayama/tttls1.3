# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  # rubocop: disable Metrics/ClassLength
  class Endpoint
    # @param label [String]
    # @param context [String]
    # @param key_length [Integer]
    # @param exporter_secret [String]
    # @param cipher_suite [TTTLS13::CipherSuite]
    #
    # @return [String, nil]
    def self.exporter(label, context, key_length, exporter_secret, cipher_suite)
      return nil if exporter_secret.nil? || cipher_suite.nil?

      digest = CipherSuite.digest(cipher_suite)
      do_exporter(exporter_secret, digest, label, context, key_length)
    end

    # @param cipher_suite [TTTLS13::CipherSuite]
    # @param write_key [String]
    # @param write_iv [String]
    #
    # @return [TTTLS13::Cryptograph::Aead]
    def self.gen_cipher(cipher_suite, write_key, write_iv)
      seq_num = SequenceNumber.new
      Cryptograph::Aead.new(
        cipher_suite: cipher_suite,
        write_key: write_key,
        write_iv: write_iv,
        sequence_number: seq_num
      )
    end

    # @param ch1 [TTTLS13::Message::ClientHello]
    # @param hrr [TTTLS13::Message::ServerHello]
    # @param ch [TTTLS13::Message::ClientHello]
    # @param binder_key [String]
    # @param digest [String] name of digest algorithm
    #
    # @return [String]
    def self.sign_psk_binder(ch1:, hrr:, ch:, binder_key:, digest:)
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
    def self.sign_certificate_verify(key:, signature_scheme:, context:, hash:)
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
    def self.verified_certificate_verify?(public_key:, signature_scheme:,
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
    def self.sign_finished(digest:, finished_key:, hash:)
      OpenSSL::HMAC.digest(digest, finished_key, hash)
    end

    # @param finished [TTTLS13::Message::Finished]
    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param hash [String]
    #
    # @return [Boolean]
    def self.verified_finished?(finished:, digest:, finished_key:, hash:)
      sign_finished(digest: digest, finished_key: finished_key, hash: hash) \
      == finished.verify_data
    end

    # @param key_exchange [String]
    # @param priv_key [OpenSSL::PKey::$Object]
    # @param group [TTTLS13::NamedGroup]
    #
    # @return [String]
    def self.gen_shared_secret(key_exchange, priv_key, group)
      curve = NamedGroup.curve_name(group)
      terminate(:internal_error) if curve.nil?

      pub_key = OpenSSL::PKey::EC::Point.new(
        OpenSSL::PKey::EC::Group.new(curve),
        OpenSSL::BN.new(key_exchange, 2)
      )

      priv_key.dh_compute_key(pub_key)
    end

    # @param certificate_list [Array of CertificateEntry]
    # @param ca_file [String] path to ca.crt
    # @param hostname [String]
    #
    # @return [Boolean]
    def self.trusted_certificate?(certificate_list,
                                  ca_file = nil,
                                  hostname = nil)
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

    # @param signature_algorithms [Array of SignatureAlgorithms]
    # @param crt [OpenSSL::X509::Certificate]
    #
    # @return [Array of TTTLS13::Message::Extension::SignatureAlgorithms]
    def self.select_signature_algorithms(signature_algorithms, crt)
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

    # @param cert [OpenSSL::X509::Certificate]
    # @param name [String]
    #
    # @return [Boolean]
    def self.matching_san?(cert, name)
      san = cert.extensions.find { |ex| ex.oid == 'subjectAltName' }
      return false if san.nil?

      ostr = OpenSSL::ASN1.decode(san.to_der).value.last
      OpenSSL::ASN1.decode(ostr.value)
                   .map(&:value)
                   .map { |s| s.gsub('.', '\.').gsub('*', '.*') }
                   .any? { |s| name.match(/#{s}/) }
    end

    class << self
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
    end
  end
  # rubocop: enable Metrics/ClassLength
end
