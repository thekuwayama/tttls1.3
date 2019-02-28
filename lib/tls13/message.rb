# encoding: ascii-8bit
# frozen_string_literal: true

Dir[File.dirname(__FILE__) + '/message/*.rb'].each { |f| require f }

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
      TLS_1_0 = "\x03\x01"
      TLS_1_1 = "\x03\x02"
      TLS_1_2 = "\x03\x03"
      TLS_1_3 = "\x03\x04"
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
  end
end
