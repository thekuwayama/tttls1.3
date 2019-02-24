module TLS13
  module Message
    module ContentType
      INVALID          = "\x00"
      CCS              = "\x14"
      ALERT            = "\x15"
      HANDSHAKE        = "\x16"
      APPLICATION_DATA = "\x17"
    end

    module ProtocolVersion
      TLS_1_0 = "\x03\x01".freeze
      TLS_1_1 = "\x03\x02".freeze
      TLS_1_2 = "\x03\x03".freeze
      TLS_1_3 = "\x03\x04".freeze
    end

    module HandshakeType
      HELLO_REQUEST        = "\x00" # RESERVED
      CLIENT_HELLO         = "\x01"
      SERVER_HELLO         = "\x02"
      HELLO_VERIFY_REQUEST = "\x03" # RESERVED
      NEW_SESSION_TICKET   = "\x04"
      END_OF_EARLY_DATA    = "\x05"
      HELLO_RETRY_REQUEST  = "\x06" # RESERVED
      ENCRYPTED_EXTENSIONS = "\x08"
      CERTIFICATE          = "\x0b"
      SERVER_KEY_EXCHANGE  = "\x0c" # RESERVED
      CERTIFICATE_REQUEST  = "\x0d"
      SERVER_HELLO_DONE    = "\x0e" # RESERVED
      CERTIFICATE_VERIFY   = "\x0f"
      CLIENT_KEY_EXCHANGE  = "\x10" # RESERVED
      FINISHED             = "\x14"
      CERTIFICATE_URL      = "\x15" # RESERVED
      CERTIFICATE_STATUS   = "\x16" # RESERVED
      SUPPLEMENTAL_DATA    = "\x17" # RESERVED
      KEY_UPDATE           = "\x18"
      MESSAGE_HASH         = "\xfe"
    end

    class Record
      attr_accessor :type
      attr_accessor :legacy_record_version
      attr_accessor :length
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
        @fragment = fragment
        @fragment = @content.serialize if fragment.nil? &&
                                          !@content.nil?
        @length = 0
        @length = @fragment.length unless @fragment.nil?
      end

      # @return [String]
      def serialize
        binary = ''
        binary << @type
        binary += @legacy_record_version
        binary += i2uint16(@length)
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
