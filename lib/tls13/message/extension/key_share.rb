module TLS13
  module Message
    module Extension
      class KeyShare
        attr_accessor :extension_type
        attr_accessor :length
        attr_accessor :msg_type
        attr_accessor :key_share_entry
        # struct {
        #     NamedGroup group;
        #     opaque key_exchange<1..2^16-1>;
        # } KeyShareEntry;

        # @param msg_type [TLS13::Message::ContentType]
        # @param key_share_entry [Array of pair of uint16, opaque]
        #
        # @return [TLS13::Message::Extension::KeyShare]
        def initialize(msg_type: ContentType::INVALID,
                       key_share_entry: [])
          @extension_type = ExtensionType::KEY_SHARE
          @msg_type = msg_type
          @length = 0
          @key_share_entry = key_share_entry || []
          @length = @key_share_entry.map { |x| 4 + x[1].length }.sum
          # TODO: check with @msg_type
        end

        # @return [Array of Integer]
        def serialize
          binary = []
          binary += @extension_type
          binary += i2uint16(@length)
          @key_share_entry.each do |entry|
            # @msg_type == HandshakeType::HELLO_RETRY_REQUEST
            # extension_data is single NamedGroup
            named_group = entry[0]
            binary += named_group
            key_exchange = entry[1]
            binary += i2uint16(key_exchange.length) + key_exchange \
              unless key_exchange.nil?
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
            key_share_entry = deserialize_keysharech(binary)
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

        # @param binary [Array of Integer]
        #
        # @return [Array of pair of uint16, opaque]
        #
        # struct {
        #     KeyShareEntry client_shares<0..2^16-1>;
        # } KeyShareClientHello;
        def self.deserialize_keysharech(**)
          # TODO
          []
        end

        # @param binary [Array of Integer]
        #
        # @return [Array of pair of uint16, opaque]
        #
        # struct {
        #     KeyShareEntry server_share;
        # } KeyShareServerHello;
        def self.deserialize_keysharesh(**)
          # TODO
          []
        end

        # @param binary [Array of Integer]
        #
        # @return [Array of pair of uint16, opaque]
        #
        # struct {
        #     NamedGroup selected_group;
        # } KeyShareHelloRetryRequest;
        def self.deserialize_keysharehrr(**)
          # TODO
          []
        end
      end
    end
  end
end
