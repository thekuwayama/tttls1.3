module TLS13
  module Message
    module ContentType
      INVALID          = 0x00
      CCS              = 0x14
      ALERT            = 0x15
      HANDSHAKE        = 0x16
      APPLICATION_DATA = 0x17
    end

    module ProtocolVersion
      TLS_1_0 = [0x03, 0x01].freeze
      TLS_1_1 = [0x03, 0x02].freeze
      TLS_1_2 = [0x03, 0x03].freeze
      TLS_1_3 = [0x03, 0x04].freeze
    end

    module HandshakeType
      HELLO_REQUEST        = 0x00 # RESERVED
      CLIENT_HELLO         = 0x01
      SERVER_HELLO         = 0x02
      HELLO_VERIFY_REQUEST = 0x03 # RESERVED
      NEW_SESSION_TICKET   = 0x04
      END_OF_EARLY_DATA    = 0x05
      HELLO_RETRY_REQUEST  = 0x06 # RESERVED
      ENCRYPTED_EXTENSIONS = 0x08
      CERTIFICATE          = 0x0b
      SERVER_KEY_EXCHANGE  = 0x0c # RESERVED
      CERTIFICATE_REQUEST  = 0x0d
      SERVER_HELLO_DONE    = 0x0e # RESERVED
      CERTIFICATE_VERIFY   = 0x0f
      CLIENT_KEY_EXCHANGE  = 0x10 # RESERVED
      FINISHED             = 0x14
      CERTIFICATE_URL      = 0x15 # RESERVED
      CERTIFICATE_STATUS   = 0x16 # RESERVED
      SUPPLEMENTAL_DATA    = 0x17 # RESERVED
      KEY_UPDATE           = 0x18
      MESSAGE_HASH         = 0xfe
    end

    class Record
      attr_accessor :type
      attr_accessor :legacy_record_version
      attr_accessor :length
      attr_accessor :fragment
      attr_accessor :content
      attr_accessor :cryptographer

      def initialize(**settings)
        # TODO
      end

      def serialize
        # TODO
      end

      def self.deserialize(data)
        # TODO
      end
    end
  end
end
