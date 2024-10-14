# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      #     struct {
      #         select (Handshake.msg_type) {
      #             case client_hello: OfferedPsks;
      #             case server_hello: uint16 selected_identity;
      #         };
      #     } PreSharedKeyExtension;
      class PreSharedKey
        attr_reader :extension_type
        attr_reader :msg_type
        attr_reader :offered_psks
        attr_reader :selected_identity

        # @param msg_type [TTTLS13::Message::ContentType]
        # @param offered_psks [TTTLS13::Message::Extension::OfferedPsks]
        # @param selected_identity [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(msg_type:, offered_psks: nil, selected_identity: '')
          @extension_type = ExtensionType::PRE_SHARED_KEY
          @msg_type = msg_type
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            @offered_psks = offered_psks
          when HandshakeType::SERVER_HELLO
            @selected_identity = selected_identity || ''
            raise Error::ErrorAlerts, :internal_error \
              unless @selected_identity.length == 2
          else
            raise Error::ErrorAlerts, :internal_error
          end
        end

        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [String]
        def serialize
          binary = ''
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            binary += @offered_psks.serialize
          when HandshakeType::SERVER_HELLO
            binary += @selected_identity
          else
            raise Error::ErrorAlerts, :internal_error
          end

          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        # @param msg_type [TTTLS13::Message::ContentType]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extensions::PreSharedKey, nil]
        def self.deserialize(binary, msg_type)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          case msg_type
          when HandshakeType::CLIENT_HELLO
            offered_psks = OfferedPsks.deserialize(binary)
            return nil if offered_psks.nil?

            PreSharedKey.new(msg_type: HandshakeType::CLIENT_HELLO,
                             offered_psks: offered_psks)
          when HandshakeType::SERVER_HELLO
            return nil unless binary.length == 2

            selected_identity = binary
            PreSharedKey.new(msg_type: HandshakeType::SERVER_HELLO,
                             selected_identity: selected_identity)
          else
            raise Error::ErrorAlerts, :internal_error
          end
        end
      end

      #     opaque PskBinderEntry<32..255>;
      #
      #     struct {
      #         PskIdentity identities<7..2^16-1>;
      #         PskBinderEntry binders<33..2^16-1>;
      #     } OfferedPsks;
      class OfferedPsks
        attr_reader :identities
        attr_reader :binders

        # @param identities [Array of PskIdentity]
        # @param binders [Array of String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(identities: [], binders: [])
          @identities = identities || []
          @binders = binders || []
          raise Error::ErrorAlerts, :internal_error \
            if @identities.empty? || @binders.empty?
        end

        # @return [String]
        def serialize
          binary = @identities.map(&:serialize).join
          identities_bin = binary.prefix_uint16_length

          binary = @binders.map(&:prefix_uint8_length).join
          binders_bin = binary.prefix_uint16_length

          identities_bin + binders_bin
        end

        # @param binary [String]
        #
        # @return [TTTLS13::Message::Extensions::OfferedPsks, nil]
        # rubocop: disable Metrics/AbcSize
        # rubocop: disable Metrics/CyclomaticComplexity
        # rubocop: disable Metrics/MethodLength
        # rubocop: disable Metrics/PerceivedComplexity
        def self.deserialize(binary)
          raise Error::ErrorAlerts, :internal_error if binary.nil?
          return nil if binary.length < 2

          pskids_len = Convert.bin2i(binary.slice(0, 2))
          i = 2
          identities = [] # Array of PskIdentity
          while i < pskids_len + 2
            return nil if i + 2 > binary.length

            id_len = Convert.bin2i(binary.slice(i, 2))
            return nil if id_len.zero?

            i += 2
            identity = binary.slice(i, id_len)
            i += id_len

            return nil if i + 4 > binary.length

            obfuscated_ticket_age = Convert.bin2i(binary.slice(i, 4))
            i += 4
            identities << PskIdentity.new(
              identity: identity,
              obfuscated_ticket_age: obfuscated_ticket_age
            )
          end

          i += 2
          binders = [] # Array of String
          while i < binary.length
            return nil if i > binary.length

            pbe_len = Convert.bin2i(binary[i])
            return nil if pbe_len < 32

            i += 1
            binders << binary.slice(i, pbe_len)
            i += pbe_len
          end
          return nil unless i == binary.length

          OfferedPsks.new(identities: identities, binders: binders)
        end
        # rubocop: enable Metrics/AbcSize
        # rubocop: enable Metrics/CyclomaticComplexity
        # rubocop: enable Metrics/MethodLength
        # rubocop: enable Metrics/PerceivedComplexity
      end

      #     struct {
      #         opaque identity<1..2^16-1>;
      #         uint32 obfuscated_ticket_age;
      #     } PskIdentity;
      class PskIdentity
        attr_reader :identity
        attr_reader :obfuscated_ticket_age

        # @param identity [String]
        # @param obfuscated_ticket_age [Integer]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(identity: '', obfuscated_ticket_age: 0)
          @identity = identity || ''
          @obfuscated_ticket_age = obfuscated_ticket_age
          raise Error::ErrorAlerts, :internal_error \
            if @identity.empty? || @obfuscated_ticket_age.negative?
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @identity.prefix_uint16_length
          binary += @obfuscated_ticket_age.to_uint32
          binary
        end
      end
    end
  end
end
