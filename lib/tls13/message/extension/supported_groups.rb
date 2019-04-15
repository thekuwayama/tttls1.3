# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements
  module Message
    module Extension
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
          # @param group [TLS13::Message::Extension::NamedGroup]
          #
          # @raise [TLS13::Error::ErrorAlerts]
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
            # NOTE:
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
          # @param groups [Array of TLS13::Message::Extension::NamedGroup]
          #
          # @raise [TLS13::Error::ErrorAlerts]
          #
          # @return [String] EC_builtin_curves
          def curve_name(group)
            case group
            when NamedGroup::SECP256R1
              'prime256v1'
            when NamedGroup::SECP384R1
              'secp384r1'
            when NamedGroup::SECP521R1
              'secp521r1'
            else
              # NOTE:
              # not supported other NamedGroup
              raise Error::ErrorAlerts, :internal_error
            end
          end
        end
      end

      class SupportedGroups
        attr_reader :extension_type
        attr_reader :named_group_list

        # @param named_group_list [Array of NamedGroup]
        #
        # @raise [TLS13::Error::ErrorAlerts]
        def initialize(named_group_list)
          @extension_type = ExtensionType::SUPPORTED_GROUPS
          @named_group_list = named_group_list || []
          raise Error::ErrorAlerts, :internal_error \
            if @named_group_list.empty? || @named_group_list.length >= 2**15 - 1
        end

        # @return [String]
        def serialize
          binary = @named_group_list.join

          @extension_type + binary.prefix_uint16_length.prefix_uint16_length
        end

        # @param binary [String]
        #
        # @raise [TLS13::Error::ErrorAlerts]
        #
        # @return [TLS13::Message::Extension::SupportedGroups, nil]
        # rubocop: disable Metrics/CyclomaticComplexity
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          return nil if binary.length < 2

          nglist_len = Convert.bin2i(binary.slice(0, 2))
          i = 2
          named_group_list = []
          while i < nglist_len + 2
            return nil if i + 2 > binary.length

            named_group_list << binary.slice(i, 2)
            i += 2
          end
          return nil unless i == binary.length &&
                            nglist_len + 2 == binary.length

          SupportedGroups.new(named_group_list)
        end
        # rubocop: enable Metrics/CyclomaticComplexity
      end
    end
  end
end
