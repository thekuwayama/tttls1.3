# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  class KeySchedule
    def initialize(psk: nil, shared_secret:, digest:)
      @digest = digest
      @hash_len = hash_len(@digest)
      @psk = psk || "\x00" * @hash_len
      @shared_secret = shared_secret # TODO: check shared_secret.length
      # @write_key_len
      # @iv_len
    end

    # @return [String]
    def early_salt
      "\x00" * @hash_len
    end

    # @return [String]
    def early_secret
      hkdf_extract(@psk, early_salt)
    end

    # @return [String]
    def client_early_traffic_secret
      derive_secret(early_secret, 'c e traffic', '')
    end

    # @return [String]
    def early_exporter_master_secret
      derive_secret(early_secret, 'e exp master', '')
    end

    # @return [String]
    def handshake_salt
      derive_secret(early_secret, 'derived', '')
    end

    # @return [String]
    def handshake_secret
      hkdf_extract(@shared_secret, handshake_salt)
    end

    # @params messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def client_handshake_traffic_secret(messages)
      derive_secret(handshake_secret, 'c hs traffic', messages)
    end

    # @params messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def server_handshake_traffic_secret(messages)
      derive_secret(handshake_secret, 's hs traffic', messages)
    end

    # @return [String]
    def master_salt
      derive_secret(handshake_secret, 'derived', '')
    end

    # @return [String]
    def master_secret
      ikm = "\x00" * @hash_len
      hkdf_extract(ikm, master_salt)
    end

    # @params messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def client_application_traffic_secret(messages)
      derive_secret(master_secret, 'c ap traffic', messages)
    end

    # @params messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def server_application_traffic_secret(messages)
      derive_secret(master_secret, 's ap traffic', messages)
    end

    # @params messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def exporter_master_secret(messages)
      derive_secret(master_secret, 'exp master', messages)
    end

    # @params messages [String] serialized ClientHello...client Finished
    #
    # @return [String]
    def resumption_master_secret(messages)
      derive_secret(master_secret, 'res master', messages)
    end

    # @params messages [String]
    #
    # @return [String]
    def transcript_hash(messages)
      OpenSSL::Digest.digest(@digest, messages)
    end

    # @params ikm [String]
    # @params salt [String]
    # @params digest [String]
    #
    # @return [String]
    def hkdf_extract(ikm, salt)
      OpenSSL::HMAC.digest(@digest, salt, ikm)
    end

    # @params secret [String]
    # @params label [String]
    # @params context [String]
    #
    # @return [String]
    def hkdf_expand_label(secret, label, context)
      binary = i2uint16(@hash_len)
      binary += uint8_length_prefix('tls13 ' + label)
      binary += uint8_length_prefix(context)
      hkdf_expand(secret, binary, @hash_len)
    end

    # @params secret [String]
    # @params info [String]
    # @params length [Integer]
    #
    # @raise [RuntimeError]
    #
    # @params [String]
    def hkdf_expand(secret, info, length)
      raise 'too long length' if length > 255 * @hash_len

      n = (length.to_f / @hash_len).ceil
      okm = ''
      t = ''
      (1..n).each do |i|
        t = OpenSSL::HMAC.digest(@digest, secret, t + info + i.chr)
        okm += t
      end
      okm[0...length]
    end

    # @params secret [String]
    # @params label [String]
    # @params messages [String]
    #
    # @return [String]
    def derive_secret(secret, label, messages)
      context = transcript_hash(messages)
      hkdf_expand_label(secret, label, context)
    end
  end
end
