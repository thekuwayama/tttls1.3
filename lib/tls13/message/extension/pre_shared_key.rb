# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      class PreSharedKey
        attr_reader   :extension_type
        attr_accessor :msg_type
        attr_accessor :offered_psks
        attr_accessor :selected_identity

        # @param msg_type [TLS13::Message::ContentType]
        # @param offered_psks [TLS13::Message::Extension::OfferedPsks]
        # @param selected_identity [String]
        #
        # @raise [RuntimeError]
        def initialize(msg_type: ContentType::INVALID,
                       offered_psks: nil,
                       selected_identity: nil)
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
            raise 'invalid msg_type'
          end
        end

        # @raise [RuntimeError]
        #
        # @return [Integer]
        def length
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            @offered_psks.length
          when HandshakeType::SERVER_HELLO
            2
          else
            raise 'invalid msg_type'
          end
        end

        # @raise [RuntimeError]
        #
        # @return [String]
        def serialize
          binary = ''
          binary += @extension_type
          binary += i2uint16(length)
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            binary += @offered_psks.serialize
          when HandshakeType::SERVER_HELLO
            binary += @selected_identity
          else
            raise 'invalid msg_type'
          end
          binary
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
            raise 'invalid msg_type'
          end
        end
      end

      class OfferedPsks
        attr_accessor :identities
        attr_accessor :binders

        # @param identities [Array of PskIdentity]
        # @param binders [Array of String]
        def initialize(identities: [], binders: [])
          @identities = identities || []
          raise 'invalid identities' if @identities.empty?

          @binders = binders || []
          raise 'invalid binders' if @binders.empty?
        end

        # @return [Integer]
        def length
          2 + @identities.map(&:length).sum \
          + 2 + @binders.length + @binders.map(&:length).sum
        end

        # @return [String]
        def serialize
          serialized_identities = i2uint16(@identities.map(&:length).sum)
          @identities.each do |psk_identity|
            serialized_identities += psk_identity.serialize
          end

          serialized_binders \
          = i2uint16(@binders.length + @binders.map(&:length).sum)
          @binders.each do |psk_binder_entry|
            serialized_binders << psk_binder_entry.length
            serialized_binders += psk_binder_entry
          end

          serialized_identities + serialized_binders
        end

        # @param binary [String]
        #
        # @return [TLS13::Message::Extensions::OfferedPsks]
        # rubocop: disable Metrics/AbcSize, Metrics/MethodLength
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

          binders_tail = itr + bin2i(binary.slice(itr, 2))
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
        # rubocop: enable Metrics/AbcSize, Metrics/MethodLength
      end

      class PskIdentity
        attr_accessor :identity
        attr_accessor :obfuscated_ticket_age

        # @param identity [String]
        # @param obfuscated_ticket_age [Integer]
        #
        # @raise [RuntimeError]
        def initialize(identity: '', obfuscated_ticket_age: 0)
          @identity = identity || ''
          raise 'invalid identity' if @identity.empty?

          @obfuscated_ticket_age = obfuscated_ticket_age
        end

        # @return [Integer]
        def length
          2 + @identity.length + 4
        end

        # @return [String]
        def serialize
          binary = ''
          binary += i2uint16(@identity.length)
          binary += @identity
          binary += i2uint32(@obfuscated_ticket_age)
          binary
        end
      end
    end
  end
end
