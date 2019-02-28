# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    class Record
      attr_accessor :type
      attr_accessor :legacy_record_version
      attr_accessor :fragment
      attr_accessor :content
      attr_accessor :cryptographer

      # @param type [TLS13::Message::ContentType]
      # @param legacy_record_version [TLS13::Message::ProtocolVersion]
      # @param fragment [String]
      # @param content [TLS13::Message::$Object]
      # @param cryptographer [TLS13::Cryptograph::$Object]
      #
      # @raise [RuntimeError]
      def initialize(type: ContentType::INVALID,
                     legacy_record_version: ProtocolVersion::TLS_1_2,
                     fragment: '',
                     content: nil,
                     cryptographer: nil)
        @type = type
        @legacy_record_version = legacy_record_version
        @content = content
        @cryptographer = cryptographer
        @fragment = fragment || ''
        @fragment = @content.serialize if fragment.nil? &&
                                          !@content.nil?
      end

      # @return [Integer]
      def length
        @fragment.length
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @type
        binary += @legacy_record_version
        binary += i2uint16(length)
        binary += @fragment
        binary
      end

      # @param binary [String]
      # @param cryptographer [TLS13::Cryptograph::$Object]
      #
      # @raise [RuntimeError]
      #
      # @return [TLS13::Message::Record]
      def self.deserialize(binary, cryptographer)
        raise 'too short binary' if binary.nil? || binary.length < 5

        type = binary[0]
        legacy_record_version = binary.slice(1, 2)
        length = bin2i(binary.slice(3, 2))
        fragment = binary.slice(5, length)
        plaintext = cryptographer.decrypt(fragment)
        content = deserialize_content(plaintext, type)
        Record.new(type: type,
                   legacy_record_version: legacy_record_version,
                   fragment: fragment,
                   content: content,
                   cryptographer: cryptographer)
      end

      # @param binary [String]
      # @param type [Integer]
      #
      # @return [TLS13::Message::$Object, nil]
      def self.deserialize_content(binary, type)
        return nil if binary.nil? || binary.empty?

        content = nil
        if type == ContentType::HANDSHAKE
          msg_type = binary[0]
          if msg_type == HandshakeType::CLIENT_HELLO
            ClientHello.deserialize(binary)
          else
            # TODO
            content = nil
          end
        else
          # TODO
          content = nil
        end
        content
      end
    end
  end
end
