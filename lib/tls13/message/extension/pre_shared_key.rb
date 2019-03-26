# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      class PreSharedKey
        attr_reader :extension_type
        attr_reader :msg_type
        attr_reader :offered_psks
        attr_reader :selected_identity

        # @param msg_type [TLS13::Message::ContentType]
        # @param offered_psks [TLS13::Message::Extension::OfferedPsks]
        # @param selected_identity [String]
        #
        # @raise [RuntimeError]
        def initialize(msg_type:, offered_psks: nil, selected_identity: '')
          @extension_type = ExtensionType::PRE_SHARED_KEY
          @msg_type = msg_type
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            @offered_psks = offered_psks
            # TODO: argument check
          when HandshakeType::SERVER_HELLO
            @selected_identity = selected_identity || ''
            # TODO: argument check
          else
            raise 'invalid HandshakeType'
          end
        end

        # @raise [RuntimeError]
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
            raise 'invalid HandshakeType'
          end

          @extension_type + uint16_length_prefix(binary)
        end

        # @param binary [String]
        # @param msg_type [TLS13::Message::ContentType]
        #
        # @raise [RuntimeError]
        #
        # @return [TLS13::Message::Extensions::PreSharedKey]
        def self.deserialize(binary, msg_type)
          case msg_type
          when HandshakeType::CLIENT_HELLO
            offered_psks = OfferedPsks.deserialize(binary)
            PreSharedKey.new(msg_type: HandshakeType::CLIENT_HELLO,
                             offered_psks: offered_psks)
          when HandshakeType::SERVER_HELLO
            raise 'malformed binary' unless binary.length == 2

            selected_identity = binary.slice(0, 2)
            PreSharedKey.new(msg_type: HandshakeType::SERVER_HELLO,
                             selected_identity: selected_identity)
          else
            raise 'unexpected HandshakeType'
          end
        end
      end

      class OfferedPsks
        attr_reader :identities
        attr_reader :binders

        # @param identities [Array of PskIdentity]
        # @param binders [Array of String]
        def initialize(identities: [], binders: [])
          @identities = identities || []
          raise 'invalid identities' if @identities.empty?

          @binders = binders || []
          raise 'invalid binders' if @binders.empty?
        end

        # @return [String]
        def serialize
          binary = @identities.map(&:serialize).join
          identities_bin = uint16_length_prefix(binary)

          binary = @binders.map { |pbe| uint8_length_prefix(pbe) }.join
          binders_bin = uint16_length_prefix(binary)

          identities_bin + binders_bin
        end

        # @param binary [String]
        #
        # @return [TLS13::Message::Extensions::OfferedPsks]
        # rubocop: disable Metrics/AbcSize
        def self.deserialize(binary)
          pksids_len = bin2i(binary.slice(0, 2))
          itr = 2
          identities = [] # Array of PskIdentity
          while itr < pksids_len + 2
            id_len = bin2i(binary.slice(itr, 2))
            itr += 2
            identity = binary.slice(itr, id_len)
            itr += id_len
            obfuscated_ticket_age = bin2i(binary.slice(itr, 4))
            itr += 4
            identities << PskIdentity.new(
              identity: identity,
              obfuscated_ticket_age: obfuscated_ticket_age
            )
          end

          binders_tail = itr + bin2i(binary.slice(itr, 2)) + 2
          itr += 2
          binders = [] # Array of String
          while itr < binders_tail
            pbe_len = bin2i(binary[itr])
            itr += 1
            binders << binary.slice(itr, pbe_len)
            itr += pbe_len
          end
          raise 'malformed binary' unless itr == binary.length

          OfferedPsks.new(identities: identities, binders: binders)
        end
        # rubocop: enable Metrics/AbcSize
      end

      class PskIdentity
        attr_reader :identity
        attr_reader :obfuscated_ticket_age

        # @param identity [String]
        # @param obfuscated_ticket_age [Integer]
        #
        # @raise [RuntimeError]
        def initialize(identity: '', obfuscated_ticket_age: 0)
          @identity = identity || ''
          raise 'invalid identity' if @identity.empty?

          @obfuscated_ticket_age = obfuscated_ticket_age
        end

        # @return [String]
        def serialize
          binary = ''
          binary += uint16_length_prefix(@identity)
          binary += i2uint32(@obfuscated_ticket_age)
          binary
        end
      end
    end
  end
end
