module TLS13
  module Message
    module Extension
      class PreSharedKey
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :msg_type
        attr_accessor :offered_psks
        attr_accessor :selected_identity

        # @param msg_type [TLS13::Message::ContentType]
        # @param offered_psks [TLS13::Message::Extension::OfferedPsks]
        # @param selected_identity [Array of Integer]
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
            @length = @offered_psks.length
            # TODO: argument check
          when HandshakeType::SERVER_HELLO
            @selected_identity = selected_identity || []
            @length = 2
            # TODO: argument check
          else
            raise 'invalid msg_type'
          end
        end

        # @raise [RuntimeError]
        #
        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
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

        # @param binary [Array of Integer]
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

            selected_identity = [binary[0], binary[1]]
            PreSharedKey.new(msg_type: HandshakeType::SERVER_HELLO,
                             selected_identity: selected_identity)
          else
            raise 'invalid msg_type'
          end
        end
      end

      class OfferedPsks
        attr_accessor :length
        attr_accessor :identities
        attr_accessor :binders

        # @param identities [Array of PskIdentity]
        # @param binders [Array of Array of Integer]
        def initialize(identities: [], binders: [])
          @identities = identities || []
          raise 'invalid identities' if @identities.empty?

          @binders = binders || []
          raise 'invalid binders' if @binders.empty?

          @length = 2 + @identities.map(&:length).sum
          @length += 2 + @binders.length + @binders.map(&:length).sum
        end

        # @return [Array of Integer]
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

        # @param binary [Array of Integer]
        #
        # @return [TLS13::Message::Extensions::OfferedPsks]
        # rubocop: disable Metrics/AbcSize, Metrics/MethodLength
        def self.deserialize(binary)
          pksids_len = arr2i([binary[0], binary[1]])
          itr = 2
          identities = [] # Array of PskIdentity
          while itr < pksids_len + 2
            id_len = arr2i([binary[itr], binary[itr + 1]])
            itr += 2
            identity = binary.slice(itr, id_len)
            itr += id_len
            obfuscated_ticket_age = arr2i(binary.slice(itr, 4))
            itr += 4
            identities << PskIdentity.new(
              identity: identity,
              obfuscated_ticket_age: obfuscated_ticket_age
            )
          end

          binders_tail = itr + arr2i([binary[itr], binary[itr + 1]])
          itr += 2
          binders = [] # Array of Array of Integer
          while itr < binders_tail
            pbe_len = binary[itr]
            itr += 1
            binders << binary.slice(itr, pbe_len)
            itr += pbe_len
          end
          OfferedPsks.new(identities: identities, binders: binders)
        end
        # rubocop: enable Metrics/AbcSize, Metrics/MethodLength
      end

      class PskIdentity
        attr_accessor :length
        attr_accessor :identity
        attr_accessor :obfuscated_ticket_age

        # @param identity [Array of Integer]
        # @param obfuscated_ticket_age [Integer]
        #
        # @raise [RuntimeError]
        def initialize(identity: [], obfuscated_ticket_age: 0)
          @identity = identity || []
          raise 'invalid identity' if @identity.empty?

          @obfuscated_ticket_age = obfuscated_ticket_age
          @length = 2 + @identity.length + 4
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += i2uint16(@identity.length)
          binary += @identity
          binary += i2uint32(@obfuscated_ticket_age)
          binary
        end
      end
    end
  end
end
