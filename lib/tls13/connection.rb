# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  CH1  = 0
  HRR  = 1
  CH   = 2
  SH   = 3
  EE   = 4
  CR   = 5
  CT   = 6
  CV   = 7
  SF   = 8
  EOED = 9
  CCT  = 10
  CCV  = 11
  CF   = 12

  # rubocop: disable Metrics/ClassLength
  class Connection
    # @param socket [Socket]
    def initialize(socket)
      @socket = socket
      @endpoint = nil # Symbol or String, :client or :server
      @key_schedule = nil # TLS13::KeySchedule
      @priv_keys = {} # Hash of NamedGroup => OpenSSL::PKey::$Object
      @read_cryptographer = Cryptograph::Passer.new
      @read_seq_num = nil # TLS13::SequenceNumber
      @write_cryptographer = Cryptograph::Passer.new
      @write_seq_num = nil # TLS13::SequenceNumber
      @transcript = {} # Hash of constant => TLS13::Message::$Object
      @message_queue = [] # Array of TLS13::Message::$Object
      @cipher_suite = nil # TLS13::CipherSuite
      @notyet_application_secret = true
    end

    # @param type [Message::ContentType]
    # @param messages [Array of TLS13::Message::$Object]
    def send_messages(type, messages)
      if @write_seq_num.nil? &&
         type == Message::ContentType::APPLICATION_DATA
        @write_seq_num = SequenceNumber.new
        sender = @endpoint
        @write_cryptographer \
        = gen_aead_with_handshake_traffic_secret(@write_seq_num, sender)
      end
      record = Message::Record.new(type: type, messages: messages,
                                   cryptographer: @write_cryptographer)
      send_record(record)
      return if messages.none? { |m| m.is_a?(Message::Finished) }

      @write_seq_num = SequenceNumber.new
      sender = @endpoint
      @write_cryptographer \
      = gen_aead_with_application_traffic_secret(@write_seq_num, sender)
    end

    # @param record [TLS13::Message::Record]
    def send_record(record)
      @socket.write(record.serialize)
      @write_seq_num&.succ
    end

    def send_ccs
      ccs_record = Message::Record.new(
        type: Message::ContentType::CCS,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [Message::ChangeCipherSpec.new],
        cryptographer: Cryptograph::Passer.new
      )
      send_record(ccs_record)
    end

    # @return [TLS13::Message::$Object]
    def recv_message
      return @message_queue.shift unless @message_queue.empty?

      loop do
        messages = []
        record = recv_record
        case record.type
        when Message::ContentType::HANDSHAKE
          messages = record.messages
        when Message::ContentType::APPLICATION_DATA
          messages = record.messages
        when Message::ContentType::CCS
          next # skip
        when Message::ContentType::ALERT
          next # TODO
        else
          raise 'unexpected ContentType'
        end
        @message_queue += messages[1..]
        return messages.first
      end
    end

    # @return [TLS13::Message::Record]
    def recv_record
      buffer = @socket.read(5)
      record_len = bin2i(buffer.slice(3, 2))
      buffer += @socket.read(record_len)
      if @read_seq_num.nil? &&
         buffer[0] == Message::ContentType::APPLICATION_DATA
        @read_seq_num = SequenceNumber.new
        sender = (@endpoint == :client ? :server : :client)
        @read_cryptographer \
        = gen_aead_with_handshake_traffic_secret(@read_seq_num, sender)
      elsif @transcript.key?(SF) && @notyet_application_secret
        @read_seq_num = SequenceNumber.new
        sender = (@endpoint == :client ? :server : :client)
        @read_cryptographer \
        = gen_aead_with_application_traffic_secret(@read_seq_num, sender)
        @notyet_application_secret = false
      end

      record = Message::Record.deserialize(buffer, @read_cryptographer)
      @read_seq_num&.succ
      record
    end

    # @param range [Range]
    #
    # @return [String]
    def concat_messages(range)
      # TODO: HRR
      range.to_a.map do |m|
        @transcript.key?(m) ? @transcript[m].serialize : ''
      end.join
    end

    # @param certificate_pem [String]
    # @param signature_scheme [TLS13::Message::SignatureScheme]
    # @param signature [String]
    # @param context [String]
    # @param message_range [Range]
    #
    # @raise [RuntimeError]
    #
    # @return [Boolean]
    def do_verify_certificate_verify(certificate_pem:, signature_scheme:,
                                     signature:, context:, message_range:)
      messages = concat_messages(message_range)
      case signature_scheme
      when Message::SignatureScheme::RSA_PSS_RSAE_SHA256
        hash = OpenSSL::Digest::SHA256.digest(messages)
        content = "\x20" * 64 + context + "\x00" + hash
        public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
        public_key.verify_pss('SHA256', signature, content, salt_length: :auto,
                                                            mgf1_hash: 'SHA256')
      else # TODO: other SignatureScheme
        raise 'unexpected SignatureScheme'
      end
    end

    # @param digest [String] name of digest algorithm
    # @param finished_key [String]
    # @param message_range [Range]
    #
    # @return [String]
    def do_sign_finished(digest:, finished_key:, message_range:)
      messages = concat_messages(message_range)
      hash = OpenSSL::Digest.digest(digest, messages)
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
      case group
      when Message::Extension::NamedGroup::SECP256R1
        pub_key = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new('prime256v1'),
          OpenSSL::BN.new(key_exchange, 2)
        )
        priv_key.dh_compute_key(pub_key)
      else # TODO: other NamedGroup
        raise 'unexpected NamedGroup'
      end
    end

    # @param seq_num [TLS13::SequenceNumber]
    # @param sender [Symbol, :client or :server]
    #
    # @return [TLS13::Cryptograph::Aead]
    def gen_aead_with_handshake_traffic_secret(seq_num, sender)
      ch_sh = concat_messages(CH..SH)
      write_key = @key_schedule.send("#{sender}_handshake_write_key", ch_sh)
      write_iv = @key_schedule.send("#{sender}_handshake_write_iv", ch_sh)
      Cryptograph::Aead.new(
        cipher_suite: @cipher_suite,
        write_key: write_key,
        write_iv: write_iv,
        sequence_number: seq_num,
        type: Message::ContentType::HANDSHAKE
      )
    end

    # @param seq_num [TLS13::SequenceNumber]
    # @param sender [Symbol, :client or :server]
    #
    # @return [TLS13::Cryptograph::Aead]
    def gen_aead_with_application_traffic_secret(seq_num, sender)
      ch_sf = concat_messages(CH..SF)
      write_key = @key_schedule.send("#{sender}_application_write_key", ch_sf)
      write_iv = @key_schedule.send("#{sender}_application_write_iv", ch_sf)
      Cryptograph::Aead.new(
        cipher_suite: @cipher_suite,
        write_key: write_key,
        write_iv: write_iv,
        sequence_number: seq_num,
        type: Message::ContentType::APPLICATION_DATA
      )
    end
  end
  # rubocop: enable Metrics/ClassLength
end
