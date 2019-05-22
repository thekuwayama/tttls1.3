# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module NamedGroup
    SECP256R1 = "\x00\x17"
    SECP384R1 = "\x00\x18"
    SECP521R1 = "\x00\x19"
    # X25519    = "\x00\x1d" # UNSUPPORTED
    # X448      = "\x00\x1e" # UNSUPPORTED
    # FFDHE2048 = "\x01\x00" # UNSUPPORTED
    # FFDHE3072 = "\x01\x01" # UNSUPPORTED
    # FFDHE4096 = "\x01\x02" # UNSUPPORTED
    # FFDHE6144 = "\x01\x03" # UNSUPPORTED
    # FFDHE8192 = "\x01\x04" # UNSUPPORTED
    # ffdhe_private_use "\x01\xfc" ~ "\x01\xff"
    # ecdhe_private_use "\xfe\x00" ~ "\xfe\xff"

    class << self
      # NOTE:
      # For secp256r1, secp384r1, and secp521r1
      #
      #     struct {
      #         uint8 legacy_form = 4;
      #         opaque X[coordinate_length];
      #         opaque Y[coordinate_length];
      #     } UncompressedPointRepresentation;
      #
      # @param group [TTTLS13::Message::Extension::NamedGroup]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [Integer]
      def key_exchange_len(group)
        case group
        when SECP256R1
          65
        when SECP384R1
          97
        when SECP521R1
          133
        # not supported other NamedGroup
        # when X25519
        #   32
        # when X448
        #   56
        # when FFDHE2048
        #   256
        # when FFDHE4096
        #   512
        # when FFDHE6144
        #   768
        # when FFDHE8192
        #   1024
        else
          raise Error::ErrorAlerts, :internal_error
        end
      end

      # NOTE:
      # SECG        |  ANSI X9.62   |  NIST
      # ------------+---------------+-------------
      # secp256r1   |  prime256v1   |   NIST P-256
      # secp384r1   |               |   NIST P-384
      # secp521r1   |               |   NIST P-521
      #
      # https://tools.ietf.org/html/rfc4492#appendix-A
      #
      # @param groups [Array of TTTLS13::Message::Extension::NamedGroup]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [String] EC_builtin_curves
      def curve_name(group)
        case group
        when SECP256R1
          'prime256v1'
        when SECP384R1
          'secp384r1'
        when SECP521R1
          'secp521r1'
        else
          # not supported other NamedGroup
          raise Error::ErrorAlerts, :internal_error
        end
      end
    end
  end
end
