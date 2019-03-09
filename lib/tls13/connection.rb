# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  class Connection
    attr_reader :state
    attr_reader :security_parameters
    attr_reader :socket
    attr_reader :handshake_hash

    def initialize(**settings)
      # TODO
    end

    def read
      # TODO
    end

    def write(data)
      # TODO
    end

    def verify_certificate_verify(signature_scheme:, certificate_pem:,
                                  signature:, transcript:)
      context = 'TLS 1.3, server CertificateVerify'
      case signature_scheme
      when SignatureScheme::RSA_PSS_RSAE_SHA256
        content = "\x20" * 64 + context + "\x00" \
                  + OpenSSL::Digest::SHA256.digest(transcript)
        public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
        public_key.verify_pss('SHA256', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA256')
      else
        raise 'unexpected SignatureScheme'
      end
    end
  end
end
