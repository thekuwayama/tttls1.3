# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module ECH
    # https://datatracker.ietf.org/doc/html/draft-sullivan-tls-signed-ech-updates-02#section-5.2.2
    module Auth
      ECHAuth = ECHConfig::ECHConfigContents::Extensions::ECHAuth
      ECHAuthInfo = ECHConfig::ECHConfigContents::Extensions::ECHAuthInfo

      # When a client retrieves an ECHConfig (e.g., from DNS), it examines the
      # ech_authinfo extension and records the set of trusted_keys for the
      # duration of that connection attempt only; these are not cached across
      # connections.
      #
      # https://datatracker.ietf.org/doc/html/draft-sullivan-tls-signed-ech-updates-02#section-5.2.2-1
      #
      # @param ech_config [ECHConfig, nil]
      #
      # @return [Array of String, nil]
      def self.trusted_keys(ech_config)
        return nil unless ECH.usable?(ech_config)

        ex = ech_config.echconfig_contents.extensions[ECHAuthInfo::TYPE]
        return nil unless ex.is_a?(ECHAuthInfo)

        ex.trusted_keys
      end

      # @param retry_configs [Array of ECHConfig]
      # @param trusted_keys [Array of String]
      # @param now [Time]
      #
      # @return [Array of ECHConfig]
      def self.authenticate(retry_configs, trusted_keys, now)
        retry_configs.filter { |c| authenticated?(c, trusted_keys, now) }
      end

      # The retry_config MUST satisfy the requirements in Section 5.1 and
      # Section 5, and MUST contain an ech_auth extension; a retry_config that
      # does not is treated as failing validation.
      #
      # https://datatracker.ietf.org/doc/html/draft-sullivan-tls-signed-ech-updates-02#section-5.2.2-2.1.1
      #
      # @param retry_config [ECHConfig]
      # @param trusted_keys [Array of String]
      # @param now [Time]
      #
      # @return [Boolean]
      def self.authenticated?(retry_config, trusted_keys, now)
        ech_auth = retry_config.echconfig_contents.extensions[ECHAuth::TYPE]
        return false unless ech_auth.is_a?(ECHAuth)

        # The client computes the SHA-256 hash of the provided spki and verifies
        # it matches one of the entries in the trusted_keys recorded from the
        # ech_authinfo of the initial ECHConfig used for this connection attempt,
        # then verifies the signature using the public key contained in spki.
        return false \
          unless trusted_keys.include?(
            OpenSSL::Digest.digest('SHA256', ech_auth.spki)
          )
        return false \
          unless verified_ech_auth?(ech_auth, retry_config.to_be_signed)

        # Validity Checking: The client verifies that not_after is strictly
        # greater than the current time.
        #
        # https://datatracker.ietf.org/doc/html/draft-sullivan-tls-signed-ech-updates-02#section-5.2.2-2.2.1
        ech_auth.not_after > now.to_i
      end

      # @param ech_auth [ECHConfig::ECHConfigContents::Extensions::ECHAuth]
      # @param to_be_signed [String]
      #
      # @return [Boolean]
      def self.verified_ech_auth?(ech_auth, to_be_signed)
        public_key = OpenSSL::PKey.read(ech_auth.spki)
        signature = ech_auth.signature

        case [ech_auth.algorithm].pack('n')
        when SignatureScheme::RSA_PSS_RSAE_SHA256,
             SignatureScheme::RSA_PSS_PSS_SHA256
          public_key.verify_pss('SHA256', signature, to_be_signed,
                                salt_length: :auto, mgf1_hash: 'SHA256')
        when SignatureScheme::RSA_PSS_RSAE_SHA384,
             SignatureScheme::RSA_PSS_PSS_SHA384
          public_key.verify_pss('SHA384', signature, to_be_signed,
                                salt_length: :auto, mgf1_hash: 'SHA384')
        when SignatureScheme::RSA_PSS_RSAE_SHA512,
             SignatureScheme::RSA_PSS_PSS_SHA512
          public_key.verify_pss('SHA512', signature, to_be_signed,
                                salt_length: :auto, mgf1_hash: 'SHA512')
        when SignatureScheme::ECDSA_SECP256R1_SHA256
          public_key.verify('SHA256', signature, to_be_signed)
        when SignatureScheme::ECDSA_SECP384R1_SHA384
          public_key.verify('SHA384', signature, to_be_signed)
        when SignatureScheme::ECDSA_SECP521R1_SHA512
          public_key.verify('SHA512', signature, to_be_signed)
        when SignatureScheme::ED25519
          public_key.verify(nil, signature, to_be_signed)
        else
          false
        end
      rescue OpenSSL::PKey::PKeyError
        false
      end
    end
  end
end
