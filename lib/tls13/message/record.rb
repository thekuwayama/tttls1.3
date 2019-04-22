# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    # https://tools.ietf.org/html/rfc8449#section-4
    DEFAULT_RECORD_SIZE_LIMIT = 2**14 + 1

    # rubocop: disable Metrics/ClassLength
    class Record
      attr_reader :type
      attr_reader :legacy_record_version
      attr_reader :messages
      attr_reader :surplus_binary
      attr_reader :cipher

      # @param type [TLS13::Message::ContentType]
      # @param legacy_record_version [TLS13::Message::ProtocolVersion]
      # @param messages [Array of TLS13::Message::$Object]
      # @param surplus_binary [String]
      # @param cipher [TLS13::Cryptograph::$Object]
      def initialize(type:,
                     legacy_record_version: ProtocolVersion::TLS_1_2,
                     messages: [],
                     surplus_binary: '',
                     cipher:)
        @type = type
        @legacy_record_version = legacy_record_version
        @messages = messages
        @surplus_binary = surplus_binary
        @cipher = cipher
      end

      # NOTE:
      # serialize joins messages.
      # If serialize is received Server Parameters(EE, CT, CV),
      # it returns one binary.
      #
      # @param record_size_limit [Integer]
      #
      # @return [String]
      def serialize(record_size_limit = DEFAULT_RECORD_SIZE_LIMIT)
        tlsplaintext = @messages.map(&:serialize).join + @surplus_binary
        if messages_type == ContentType::APPLICATION_DATA
          max = cipher.tlsplaintext_length_limit(record_size_limit)
          fragments = tlsplaintext.scan(/.{1,#{max}}/m)
        else
          fragments = [tlsplaintext]
        end
        fragments = [''] if fragments.empty?

        binary = ''
        fragments.each do |s|
          binary += @type + @legacy_record_version
          binary += @cipher.encrypt(s, messages_type).prefix_uint16_length
        end

        binary
      end

      # NOTE:
      # If previous Record has surplus_binary,
      # surplus_binary should is given to Record.deserialize as buffered.
      #
      # @param binary [String]
      # @param cipher [TLS13::Cryptograph::$Object]
      # @param buffered [String] surplus_binary
      #
      # @raise [TLS13::Error::ErrorAlerts]
      #
      # @return [TLS13::Message::Record, String]
      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/PerceivedComplexity
      def self.deserialize(binary, cipher, buffered = '')
        raise Error::ErrorAlerts, :internal_error if binary.nil?
        raise Error::ErrorAlerts, :decode_error if binary.length < 5

        type = binary[0]
        legacy_record_version = binary.slice(1, 2)
        fragment_len = Convert.bin2i(binary.slice(3, 2))
        raise Error::ErrorAlerts, :record_overflow \
          if (cipher.is_a?(Cryptograph::Passer) && fragment_len > 2**14) ||
             (cipher.is_a?(Cryptograph::Aead) && fragment_len > 2**14 + 256)

        fragment = binary.slice(5, fragment_len)
        raise Error::ErrorAlerts, :decode_error \
          unless binary.length == 5 + fragment_len

        if type == ContentType::APPLICATION_DATA
          fragment, inner_type = cipher.decrypt(fragment, binary.slice(0, 5))
        end
        messages, surplus_binary = deserialize_fragment(buffered + fragment,
                                                        inner_type || type)

        Record.new(type: type,
                   legacy_record_version: legacy_record_version,
                   messages: messages,
                   surplus_binary: surplus_binary,
                   cipher: cipher)
      end
      # rubocop: enable Metrics/CyclomaticComplexity
      # rubocop: enable Metrics/PerceivedComplexity

      private

      # @raise [TLS13::Error::ErrorAlerts]
      #
      # @return [TLS13::Message::ContentType]
      def messages_type
        types = @messages.map(&:class).uniq
        raise Error::ErrorAlerts, :internal_error unless types.length == 1

        type = types.first
        if [Message::ClientHello,
            Message::ServerHello,
            Message::EncryptedExtensions,
            Message::Certificate,
            Message::CertificateVerify,
            Message::Finished,
            Message::EndOfEarlyData,
            Message::NewSessionTicket].include?(type)
          ContentType::HANDSHAKE
        elsif type == ChangeCipherSpec
          ContentType::CCS
        elsif type == Message::ApplicationData
          ContentType::APPLICATION_DATA
        elsif type == Message::Alert
          ContentType::ALERT
        else
          raise Error::ErrorAlerts, :internal_error
        end
      end

      class << self
        private

        # @param binary [String]
        # @param type [TLS13::Message::ContentType]
        #
        # @raise [TLS13::Error::ErrorAlerts]
        #
        # @return [Array of TLS13::Message::$Object, String]
        # @return [String]
        def deserialize_fragment(binary, type)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          surplus_binary = ''
          case type
          when ContentType::HANDSHAKE
            messages, surplus_binary = deserialize_handshake(binary)
          when ContentType::CCS
            messages = [ChangeCipherSpec.deserialize(binary)]
          when ContentType::APPLICATION_DATA
            messages = [ApplicationData.deserialize(binary)]
          when ContentType::ALERT
            messages = [Alert.deserialize(binary)]
          else
            raise Error::ErrorAlerts, :unexpected_message
          end

          [messages, surplus_binary]
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::ErrorAlerts]
        #
        # @return [Array of TLS13::Message::$Object]
        # @return [String]
        def deserialize_handshake(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          handshakes = []
          i = 0
          while i < binary.length
            # Handshake.length is kind of uint24 and Record.length is kind of
            # uint16, so Handshake can be longer than Record capacity.
            if binary.length < 4 + i ||
               binary.length < 4 + i + Convert.bin2i(binary.slice(i + 1, 3))
              surplus_binary = binary[i..]
              return [handshakes, surplus_binary]
            end

            msg_len = Convert.bin2i(binary.slice(i + 1, 3))
            msg_bin = binary.slice(i, msg_len + 4)
            message = do_deserialize_handshake(msg_bin)
            i += msg_len + 4
            handshakes << message
          end

          surplus_binary = binary[i..]
          [handshakes, surplus_binary]
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::ErrorAlerts]
        #
        # @return [Array of TLS13::Message::$Object]
        # rubocop: disable Metrics/CyclomaticComplexity
        def do_deserialize_handshake(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?
          raise Error::ErrorAlerts, :decode_error if binary.empty?

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
          when HandshakeType::END_OF_EARLY_DATA
            EndOfEarlyData.deserialize(binary)
          else
            raise Error::ErrorAlerts, :unexpected_message
          end
        end
        # rubocop: enable Metrics/CyclomaticComplexity
      end
    end
    # rubocop: enable Metrics/ClassLength
  end
end
