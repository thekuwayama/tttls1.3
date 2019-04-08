# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    # rubocop: disable Metrics/ClassLength
    class Record
      attr_reader :type
      attr_reader :legacy_record_version
      attr_reader :messages
      attr_reader :cipher

      # @param type [TLS13::Message::ContentType]
      # @param legacy_record_version [TLS13::Message::ProtocolVersion]
      # @param messages [Array of TLS13::Message::$Object]
      # @param cipher [TLS13::Cryptograph::$Object]
      def initialize(type:,
                     legacy_record_version: ProtocolVersion::TLS_1_2,
                     messages: [],
                     cipher:)
        @type = type
        @legacy_record_version = legacy_record_version
        @messages = messages || []
        @cipher = cipher
      end

      # @return [String]
      def serialize
        binary = ''
        binary += @type
        binary += @legacy_record_version
        fragment = @cipher.encrypt(@messages.map(&:serialize).join,
                                   messages_type)
        binary += fragment.prefix_uint16_length
        binary
      end

      # @param binary [String]
      # @param cipher [TLS13::Cryptograph::$Object]
      #
      # @raise [TLS13::Error::TLSError]
      #
      # @return [TLS13::Message::Record]
      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/PerceivedComplexity
      def self.deserialize(binary, cipher)
        raise Error::TLSError, :internal_error if binary.nil?
        raise Error::TLSError, :decode_error if binary.length < 5

        type = binary[0]
        legacy_record_version = binary.slice(1, 2)
        fragment_len = Convert.bin2i(binary.slice(3, 2))
        raise Error::TLSError, :record_overflow \
          if (cipher.is_a?(Cryptograph::Passer) && fragment_len > 2**14) ||
             (cipher.is_a?(Cryptograph::Aead) && fragment_len > 2**14 + 256)

        fragment = binary.slice(5, fragment_len)
        raise Error::TLSError, :decode_error \
          unless binary.length == 5 + fragment_len

        if type == ContentType::APPLICATION_DATA
          fragment, inner_type = cipher.decrypt(fragment, binary.slice(0, 5))
        end
        messages = deserialize_fragment(fragment, inner_type || type)
        Record.new(type: type,
                   legacy_record_version: legacy_record_version,
                   messages: messages,
                   cipher: cipher)
      end
      # rubocop: enable Metrics/CyclomaticComplexity
      # rubocop: enable Metrics/PerceivedComplexity

      private

      # @raise [TLS13::Error::TLSError]
      #
      # @return [TLS13::Message::ContentType]
      def messages_type
        types = @messages.map(&:class).uniq
        raise Error::TLSError, :internal_error unless types.length == 1

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
          raise Error::TLSError, :internal_error
        end
      end

      class << self
        private

        # @param binary [String]
        # @param type [TLS13::Message::ContentType]
        #
        # @raise [TLS13::Error::TLSError]
        #
        # @return [Array of TLS13::Message::$Object]
        def deserialize_fragment(binary, type)
          raise Error::TLSError, :internal_error if binary.nil?

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
            raise Error::TLSError, :unexpected_message
          end
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::TLSError]
        #
        # @return [Array of TLS13::Message::$Object]
        def deserialize_handshake(binary)
          raise Error::TLSError, :internal_error if binary.nil?

          handshakes = []
          i = 0
          while i < binary.length
            raise Error::TLSError, :decode_error if i + 4 > binary.length

            msg_len = Convert.bin2i(binary.slice(i + 1, 3))
            msg_bin = binary.slice(i, msg_len + 4)
            message = do_deserialize_handshake(msg_bin)
            i += msg_len + 4
            handshakes << message
          end
          raise Error::TLSError, :decode_error unless i == binary.length

          handshakes
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::TLSError]
        #
        # @return [Array of TLS13::Message::$Object]
        # rubocop: disable Metrics/CyclomaticComplexity
        def do_deserialize_handshake(binary)
          raise Error::TLSError, :internal_error if binary.nil?
          raise Error::TLSError, :decode_error if binary.empty?

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
            raise Error::TLSError, :unexpected_message
          end
        end
        # rubocop: enable Metrics/CyclomaticComplexity
      end
    end
    # rubocop: enable Metrics/ClassLength
  end
end
