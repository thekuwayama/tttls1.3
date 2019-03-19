# encoding: ascii-8bit
# frozen_string_literal: true

require 'openssl'

module TLS13
  # rubocop: disable Metrics/ClassLength
  class KeySchedule
    def initialize(psk: nil, shared_secret:, cipher_suite:)
      @digest = CipherSuite.digest(cipher_suite)
      @hash_len = CipherSuite.hash_len(cipher_suite)
      @key_len = CipherSuite.key_len(cipher_suite)
      @iv_len = CipherSuite.iv_len(cipher_suite)
      @psk = psk || "\x00" * @hash_len
      @shared_secret = shared_secret
      # TODO: check shared_secret.length
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

    # @param messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def client_handshake_traffic_secret(messages)
      derive_secret(handshake_secret, 'c hs traffic', messages)
    end

    # @param messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def client_finished_key(messages)
      secret = client_handshake_traffic_secret(messages)
      hkdf_expand_label(secret, 'finished', '', @hash_len)
    end

    # @param messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def client_handshake_write_key(messages)
      secret = client_handshake_traffic_secret(messages)
      hkdf_expand_label(secret, 'key', '', @key_len)
    end

    # @param messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def client_handshake_write_iv(messages)
      secret = client_handshake_traffic_secret(messages)
      hkdf_expand_label(secret, 'iv', '', @iv_len)
    end

    # @param messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def server_handshake_traffic_secret(messages)
      derive_secret(handshake_secret, 's hs traffic', messages)
    end

    # @param messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def server_finished_key(messages)
      secret = server_handshake_traffic_secret(messages)
      hkdf_expand_label(secret, 'finished', '', @hash_len)
    end

    # @param messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def server_handshake_write_key(messages)
      secret = server_handshake_traffic_secret(messages)
      hkdf_expand_label(secret, 'key', '', @key_len)
    end

    # @param messages [String] serialized ClientHello and ServerHello
    #
    # @return [String]
    def server_handshake_write_iv(messages)
      secret = server_handshake_traffic_secret(messages)
      hkdf_expand_label(secret, 'iv', '', @iv_len)
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

    # @param messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def client_application_traffic_secret(messages)
      derive_secret(master_secret, 'c ap traffic', messages)
    end

    # @param messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def client_application_write_key(messages)
      secret = client_application_traffic_secret(messages)
      hkdf_expand_label(secret, 'key', '', @key_len)
    end

    # @param messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def client_application_write_iv(messages)
      secret = client_application_traffic_secret(messages)
      hkdf_expand_label(secret, 'iv', '', @iv_len)
    end

    # @param messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def server_application_traffic_secret(messages)
      derive_secret(master_secret, 's ap traffic', messages)
    end

    # @param messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def server_application_write_key(messages)
      secret = server_application_traffic_secret(messages)
      hkdf_expand_label(secret, 'key', '', @key_len)
    end

    # @param messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def server_application_write_iv(messages)
      secret = server_application_traffic_secret(messages)
      hkdf_expand_label(secret, 'iv', '', @iv_len)
    end

    # @param messages [String] serialized ClientHello...server Finished
    #
    # @return [String]
    def exporter_master_secret(messages)
      derive_secret(master_secret, 'exp master', messages)
    end

    # @param messages [String] serialized ClientHello...client Finished
    #
    # @return [String]
    def resumption_master_secret(messages)
      derive_secret(master_secret, 'res master', messages)
    end

    # @param messages [String]
    #
    # @return [String]
    def transcript_hash(messages)
      OpenSSL::Digest.digest(@digest, messages)
    end

    # @param ikm [String]
    # @param salt [String]
    #
    # @return [String]
    def hkdf_extract(ikm, salt)
      OpenSSL::HMAC.digest(@digest, salt, ikm)
    end

    # @param secret [String]
    # @param label [String]
    # @param context [String]
    # @param length [Integer]
    #
    # @return [String]
    def hkdf_expand_label(secret, label, context, length)
      binary = i2uint16(length)
      binary += uint8_length_prefix('tls13 ' + label)
      binary += uint8_length_prefix(context)
      hkdf_expand(secret, binary, length)
    end

    # @param secret [String]
    # @param info [String]
    # @param length [Integer]
    #
    # @raise [RuntimeError]
    #
    # @param [String]
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

    # @param secret [String]
    # @param label [String]
    # @param messages [String]
    #
    # @return [String]
    def derive_secret(secret, label, messages)
      context = transcript_hash(messages)
      hkdf_expand_label(secret, label, context, @hash_len)
    end
  end
  # rubocop: enable Metrics/ClassLength
end
