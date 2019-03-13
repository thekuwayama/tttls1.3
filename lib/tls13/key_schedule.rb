# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  class KeySchedule
    def initialize(psk: nil, digest:)
      @digest = digest
      @hash_len = hash_len(@digest)
      @psk = psk || "\x00" * @hash_len
    end

    # @return [String]
    def early_salt
      "\x00" * @hash_len
    end

    # @return [String]
    def client_early_traffic_secret
      derive_secret(@psk, early_salt, 'c e traffic', '')
    end

    # @return [String]
    def early_exporter_master_secret
      derive_secret(@psk, early_salt, 'e exp master', '')
    end

    # @return [String]
    def handshake_salt
      derive_secret(@psk, early_salt, 'derived', '')
    end

    # @params shared_secret [String] (EC)DHE
    # @params messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def client_handshake_traffic_secret(shared_secret, messages)
      derive_secret(shared_secret, handshake_salt, 'c hs traffic', messages)
    end

    # @params shared_secret [String] (EC)DHE
    # @params messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def server_handshake_traffic_secret(shared_secret, messages)
      derive_secret(shared_secret, handshake_salt, 's hs traffic', messages)
    end

    # @params shared_secret [String] (EC)DHE
    #
    # @return [String]
    def master_salt(shared_secret)
      derive_secret(shared_secret, handshake_salt, 'derived', '')
    end

    # @params shared_secret [String] (EC)DHE
    # @params messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def client_application_traffic_secret(shared_secret, messages)
      ikm = "\x00" * @hash_len
      salt = master_salt(shared_secret)
      derive_secret(ikm, salt, 'c ap traffic', messages)
    end

    # @params shared_secret [String] (EC)DHE
    # @params messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def server_application_traffic_secret(shared_secret, messages)
      ikm = "\x00" * @hash_len
      salt = master_salt(shared_secret)
      derive_secret(ikm, salt, 's ap traffic', messages)
    end

    # @params shared_secret [String] (EC)DHE
    # @params messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def exporter_master_secret(shared_secret, messages)
      ikm = "\x00" * @hash_len
      salt = master_salt(shared_secret)
      derive_secret(ikm, salt, 'exp master', messages)
    end

    # @params shared_secret [String] (EC)DHE
    # @params messages [String] serialized ClientHello...client Finished
    #
    # @return [String]
    def resumption_master_secret(shared_secret, messages)
      ikm = "\x00" * @hash_len
      salt = master_salt(shared_secret)
      derive_secret(ikm, salt, 'res master', messages)
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

    # @params ikm [String]
    # @params salt [String]
    # @params label [String]
    # @params context [String]
    #
    # @return [String]
    def hkdf_expand_label(ikm, salt, label, context)
      binary = i2uint16(@hash_len)
      label = 'tls13 ' + label
      binary += i2uint8(label.length)
      binary += label
      binary += i2uint8(context.length)
      binary += context
      hash = OpenSSL::Digest.new(@digest)
      OpenSSL::KDF.hkdf(ikm, salt: salt, info: binary, length: @hash_len,
                             hash: hash)
    end

    # @params ikm [String]
    # @params salt [String]
    # @params label [String]
    # @params messages [String]
    #
    # @return [String]
    def derive_secret(ikm, salt, label, messages)
      context = transcript_hash(messages)
      hkdf_expand_label(ikm, salt, label, context)
    end
  end
end
