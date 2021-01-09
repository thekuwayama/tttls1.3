# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Message
    module ContentType
      INVALID          = "\x00"
      CCS              = "\x14"
      ALERT            = "\x15"
      HANDSHAKE        = "\x16"
      APPLICATION_DATA = "\x17"
    end

    module ProtocolVersion
      TLS_1_0 = "\x03\x01"
      TLS_1_1 = "\x03\x02"
      TLS_1_2 = "\x03\x03"
      TLS_1_3 = "\x03\x04"
    end

    DEFAULT_VERSIONS = [ProtocolVersion::TLS_1_3].freeze

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

    module ExtensionType
      SERVER_NAME                            = "\x00\x00"
      MAX_FRAGMENT_LENGTH                    = "\x00\x01"
      STATUS_REQUEST                         = "\x00\x05"
      SUPPORTED_GROUPS                       = "\x00\x0a"
      SIGNATURE_ALGORITHMS                   = "\x00\x0d"
      USE_SRTP                               = "\x00\x0e"
      HEARTBEAT                              = "\x00\x0f"
      APPLICATION_LAYER_PROTOCOL_NEGOTIATION = "\x00\x10"
      SIGNED_CERTIFICATE_TIMESTAMP           = "\x00\x12"
      CLIENT_CERTIFICATE_TYPE                = "\x00\x13"
      SERVER_CERTIFICATE_TYPE                = "\x00\x14"
      PADDING                                = "\x00\x15"
      COMPRESS_CERTIFICATE                   = "\x00\x1b"
      RECORD_SIZE_LIMIT                      = "\x00\x1c"
      PWD_PROTECT                            = "\x00\x1d"
      PWD_CLEAR                              = "\x00\x1e"
      PASSWORD_SALT                          = "\x00\x1f"
      PRE_SHARED_KEY                         = "\x00\x29"
      EARLY_DATA                             = "\x00\x2a"
      SUPPORTED_VERSIONS                     = "\x00\x2b"
      COOKIE                                 = "\x00\x2c"
      PSK_KEY_EXCHANGE_MODES                 = "\x00\x2d"
      CERTIFICATE_AUTHORITIES                = "\x00\x2f"
      OID_FILTERS                            = "\x00\x30"
      POST_HANDSHAKE_AUTH                    = "\x00\x31"
      SIGNATURE_ALGORITHMS_CERT              = "\x00\x32"
      KEY_SHARE                              = "\x00\x33"
    end

    DEFINED_EXTENSIONS = ExtensionType.constants.map do |c|
      ExtensionType.const_get(c)
    end.freeze
  end
end

Dir[File.dirname(__FILE__) + '/message/*.rb'].sort.each { |f| require f }
