# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    # rubocop: disable Metrics/ClassLength
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

      # @return [String]
      def serialize
        binary = ''
        binary += @type
        binary += @legacy_record_version
        fragment = @cryptographer.encrypt(@messages.map(&:serialize).join,
                                          messages_type)
        binary += uint16_length_prefix(fragment)
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
        fragment_len = bin2i(binary.slice(3, 2))
        fragment = binary.slice(5, fragment_len)
        if type == ContentType::APPLICATION_DATA
          fragment, inner_type \
                    = cryptographer.decrypt(fragment, binary.slice(0, 5))
        end
        messages = deserialize_fragment(fragment, inner_type || type)
        Record.new(type: type,
                   legacy_record_version: legacy_record_version,
                   messages: messages,
                   cryptographer: cryptographer)
      end

      private

      def messages_type
        types = @messages.map(&:class).uniq
        raise 'invalid messages' unless types.length == 1

        type = types.first
        if [Message::ClientHello,
            Message::ServerHello,
            Message::EncryptedExtensions,
            Message::Certificate,
            Message::CertificateVerify,
            Message::Finished,
            Message::NewSessionTicket].include?(type)
          ContentType::HANDSHAKE
        elsif type == ChangeCipherSpec
          ContentType::CCS
        elsif type == Message::ApplicationData
          ContentType::APPLICATION_DATA
        elsif type == Message::Alert
          ContentType::ALERT
        else
          raise 'unexpected messages'
        end
      end

      class << self
        # @param binary [String]
        # @param type [TLS13::Message::ContentType]
        #
        # @raise [RuntimeError]
        #
        # @return [Array of TLS13::Message::$Object]
        def deserialize_fragment(binary, type)
          raise 'zero-length fragments' if binary.nil? || binary.empty?

          case type
          when ContentType::HANDSHAKE
            deserialize_handshake(binary)
          when ContentType::CCS
            [ChangeCipherSpec.deserialize(binary)]
          when ContentType::APPLICATION_DATA
            [ApplicationData.deserialize(binary)]
          when ContentType::ALERT
            [Alert.deserialize(binary)]
          else
            raise 'unknown ContentType'
          end
        end

        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [Array of TLS13::Message::$Object]
        # rubocop: disable Metrics/CyclomaticComplexity
        def do_deserialize_handshake(binary)
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
            Finished.deserialize(binary)
          when HandshakeType::NEW_SESSION_TICKET
            NewSessionTicket.deserialize(binary)
          else
            raise 'unexpected HandshakeType'
          end
        end
        # rubocop: enable Metrics/CyclomaticComplexity

        # @param binary [String]
        #
        # @return [Array of TLS13::Message::$Object]
        def deserialize_handshake(binary)
          handshakes = []
          itr = 0
          while itr < binary.length
            msg_len = bin2i(binary.slice(itr + 1, 3))
            msg_bin = binary.slice(itr, msg_len + 4)
            message = do_deserialize_handshake(msg_bin)
            itr += msg_len + 4
            handshakes << message
          end
          raise 'malformed binary' unless itr == binary.length

          handshakes
        end
      end
    end
    # rubocop: enable Metrics/ClassLength
  end
end
