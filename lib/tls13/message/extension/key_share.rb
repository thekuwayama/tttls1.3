module TLS13
  module Message
    module Extension
      class KeyShare
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :msg_type
        attr_accessor :key_share_entry

        # @param msg_type [TLS13::Message::ContentType]
        # @param key_share_entry [Array of KeyShareEntry]
        #
        # @raise [RuntimeError]
        def initialize(msg_type: ContentType::INVALID,
                       key_share_entry: [])
          @extension_type = ExtensionType::KEY_SHARE
          @msg_type = msg_type
          @length = 0
          @key_share_entry = key_share_entry || []
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            @length = 2
            @length += @key_share_entry.map do |x|
              4 + x.key_exchange.length
            end.sum
          when HandshakeType::SERVER_HELLO
            @length = 4 + @key_share_entry.first.key_exchange.length
          when HandshakeType::HELLO_RETRY_REQUEST
            @length = 2
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
            buf = []
            @key_share_entry.each do |entry|
              buf += entry.serialize
            end
            binary += i2uint16(buf.length)
            binary += buf
          when HandshakeType::SERVER_HELLO
            binary += @key_share_entry.first.serialize
          when HandshakeType::HELLO_RETRY_REQUEST
            binary += @key_share_entry.first.serialize
          else
            raise 'invalid msg_type'
          end
          binary
        end

        # @param binary [Array of Integer]
        # @param msg_type [TLS13::Message::HandshakeType]
        #
        # @return [TLS13::Message::Extensions::KeyShare]
        def self.deserialize(binary, msg_type)
          key_share_entry = []
          case msg_type
          when HandshakeType::CLIENT_HELLO
            kse_len = arr2i([binary[0], binary[1]])
            key_share_entry = deserialize_keysharech(binary.slice(2, kse_len))
          when HandshakeType::SERVER_HELLO
            key_share_entry = deserialize_keysharesh(binary)
          when HandshakeType::HELLO_RETRY_REQUEST
            key_share_entry = deserialize_keysharehrr(binary)
          else
            return UknownExtension.new(extension_type: @extension_type,
                                       extension_data: binary)
          end
          KeyShare.new(msg_type: msg_type,
                       key_share_entry: key_share_entry)
        end

        # struct {
        #     KeyShareEntry client_shares<0..2^16-1>;
        # } KeyShareClientHello;
        # @param binary [Array of Integer]
        #
        # @return [Array of KeyShareEntry]
        def self.deserialize_keysharech(binary)
          key_share_entry = []
          itr = 0
          while itr < binary.length
            group = [binary[itr], binary[itr + 1]]
            itr += 2
            ke_len = arr2i([binary[itr], binary[itr + 1]])
            itr += 2
            key_exchange = binary.slice(itr, ke_len)
            key_share_entry << KeyShareEntry.new(group: group,
                                                 key_exchange: key_exchange)
            itr += ke_len
          end
          key_share_entry
        end

        # struct {
        #     KeyShareEntry server_share;
        # } KeyShareServerHello;
        # @param binary [Array of Integer]
        #
        # @return [Array of KeyShareEntry]
        def self.deserialize_keysharesh(binary)
          itr = 0
          group = [binary[itr] + binary[itr + 1]]
          itr += 2
          ke_len = arr2i([binary[itr] + binary[itr + 1]])
          itr += 2
          key_exchange = binary.slice(itr, ke_len)
          [KeyShareEntry.new(group: group, key_exchange: key_exchange)]
        end

        # struct {
        #     NamedGroup selected_group;
        # } KeyShareHelloRetryRequest;
        #
        # @param binary [Array of Integer]
        #
        # @return [Array of KeyShareEntry]
        def self.deserialize_keysharehrr(binary)
          group = [binary[0] + binary[1]]
          [KeyShareEntry.new(group: group)]
        end
      end

      class KeyShareEntry
        attr_accessor :group
        attr_accessor :key_exchange

        # @param group [TLS13::Message::Extension::NamedGroup]
        # @param key_exchange [Array of Integer]
        def initialize(group: [], key_exchange: [])
          @group = group
          @key_exchange = key_exchange
          # TODO: check len(key_exchange) for group
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          # @msg_type == HandshakeType::HELLO_RETRY_REQUEST
          # extension_data is single NamedGroup
          binary += @group
          binary += i2uint16(@key_exchange.length) + @key_exchange \
            unless @key_exchange.nil? || @key_exchange.empty?
          binary
        end
      end
    end
  end
end
