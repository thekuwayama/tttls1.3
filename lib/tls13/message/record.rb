# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class << self
      # @param binary [String]
      # @param hash_len [Integer]
      #
      # @raise [RuntimeError]
      #
      # @return [Array of TLS13::Message::$Object]
      # rubocop: disable Metrics/CyclomaticComplexity
      def deserialize_handshake(binary, hash_len)
        case binary[0]
        when HandshakeType::CLIENT_HELLO
          ClientHello.deserialize(binary)
        when HandshakeType::SERVER_HELLO
          ServerHello.deserialize(binary)
        when HandshakeType::ENCRYPTED_EXTENSIONS
          EncryptedExtensions.deserialize(binary)
        when HandshakeType::CERTIFICATE
          Certificate.deserialize(binary)
        when HandshakeType::CERTIFICATE_VERIFY
          CertificateVerify.deserialize(binary)
        when HandshakeType::FINISHED
          Finished.deserialize(binary, hash_len)
        else
          raise 'unexpected HandshakeType'
        end
      end
      # rubocop: enable Metrics/CyclomaticComplexity

      # @param binary [String]
      # @param hash_len [Integer]
      #
      # @return [Array of TLS13::Message::$Object]
      def deserialize_server_parameters(binary, hash_len)
        handshakes = []
        itr = 0
        while itr < binary.length
          msg_len = bin2i(binary.slice(itr + 1, 3))
          msg_bin = binary.slice(itr, msg_len + 4)
          message = deserialize_handshake(msg_bin, hash_len)
          itr += msg_len + 4
          handshakes << message
        end
        raise 'malformed binary' unless itr == binary.length

        handshakes
      end
    end

    class Record
      attr_reader :type
      attr_reader :legacy_record_version
      attr_reader :messages
      attr_reader :cryptographer

      # @param type [TLS13::Message::ContentType]
      # @param legacy_record_version [TLS13::Message::ProtocolVersion]
      # @param messages [Array of TLS13::Message::$Object]
      # @param cryptographer [TLS13::Cryptograph::$Object]
      #
      # @raise [RuntimeError]
      def initialize(type:,
                     legacy_record_version: ProtocolVersion::TLS_1_2,
                     messages: [],
                     cryptographer:)
        @type = type
        @legacy_record_version = legacy_record_version
        @messages = messages || []
        @cryptographer = cryptographer
      end

      # @raise [RuntimeError]
      #
      # @return [Integer]
      def length
        case @type
        when ContentType::HANDSHAKE
          @messages.map { |x| x.length + 4 }.sum
        when ContentType::CCS
          1
        when ContentType::APPLICATION_DATA
          @fragment.length
        else # TODO
          raise 'unexpected ContentType'
        end
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @type
        binary += @legacy_record_version
        fragment = @cryptographer.encrypt(@messages.map(&:serialize).join)
        binary += uint16_length_prefix(fragment)
        binary
      end

      # @param binary [String]
      # @param cryptographer [TLS13::Cryptograph::$Object]
      # @param hash_len [Integer]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Record]
      def self.deserialize(binary, cryptographer, *hash_len)
        raise 'too short binary' if binary.nil? || binary.length < 5

        type = binary[0]
        legacy_record_version = binary.slice(1, 2)
        fragment_len = bin2i(binary.slice(3, 2))
        fragment = binary.slice(5, fragment_len)
        plaintext = fragment
        plaintext = cryptographer.decrypt(fragment, binary.slice(0, 5)) \
          if type == ContentType::APPLICATION_DATA
        messages = deserialize_fragment(plaintext, type, hash_len)
        Record.new(type: type,
                   legacy_record_version: legacy_record_version,
                   messages: messages,
                   cryptographer: cryptographer)
      end

      # @param binary [String]
      # @param type [TLS13::Message::ContentType]
      # @param hash_len [Integer]
      #
      # @raise [RuntimeError]
      #
      # @return [Array of TLS13::Message::$Object]
      def self.deserialize_fragment(binary, type, hash_len)
        raise 'zero-length fragments' if binary.nil? || binary.empty?

        case type
        when ContentType::HANDSHAKE
          [Message.deserialize_handshake(binary, hash_len)]
        when ContentType::CCS
          [ChangeCipherSpec.deserialize(binary)]
        when ContentType::APPLICATION_DATA
          [ApplicationData.deserialize(binary)]
        else
          raise 'unknown ContentType'
        end
      end
    end
  end
end
