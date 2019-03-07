# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      class KeyShare
        attr_reader :extension_type
        attr_reader :msg_type
        attr_reader :key_share_entry

        # @param msg_type [TLS13::Message::ContentType]
        # @param key_share_entry [Array of KeyShareEntry]
        #
        # @raise [RuntimeError]
        # rubocop: disable Metrics/CyclomaticComplexity
        # rubocop: disable Metrics/PerceivedComplexity
        def initialize(msg_type:, key_share_entry: [])
          @extension_type = ExtensionType::KEY_SHARE
          @msg_type = msg_type
          @key_share_entry = key_share_entry || []
          if @msg_type == HandshakeType::SERVER_HELLO
            raise 'invalid KeyShareServerHello' \
              unless @key_share_entry.length == 1 &&
                     @key_share_entry.first.key_share_server_hello?
          elsif @msg_type == HandshakeType::HELLO_RETRY_REQUEST
            raise 'invalid KeyShareHelloRetryRequest' \
              unless @key_share_entry.length == 1 &&
                     @key_share_entry.first.key_share_hello_retry_request?
          elsif @msg_type != HandshakeType::CLIENT_HELLO
            raise 'invalid HandshakeType'
          end
        end
        # rubocop: enable Metrics/CyclomaticComplexity
        # rubocop: enable Metrics/PerceivedComplexity

        # @raise [RuntimeError]
        #
        # @return [Integer]
        def length
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            2 + @key_share_entry.map do |x|
              4 + x.key_exchange.length
            end.sum
          when HandshakeType::SERVER_HELLO
            4 + @key_share_entry.first.key_exchange.length
          when HandshakeType::HELLO_RETRY_REQUEST
            2
          else
            raise 'unexpected HandshakeType'
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
            buf = ''
            @key_share_entry.each do |entry|
              buf += entry.serialize
            end
            binary += i2uint16(buf.length)
            binary += buf
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            binary += @key_share_entry.first.serialize
          else
            raise 'unexpected HandshakeType'
          end
          binary
        end

        # @param binary [String]
        # @param msg_type [TLS13::Message::HandshakeType]
        #
        # @return [TLS13::Message::Extensions::KeyShare, UknownExtension]
        def self.deserialize(binary, msg_type)
          key_share_entry = []
          case msg_type
          when HandshakeType::CLIENT_HELLO
            key_share_entry = deserialize_keyshare_ch(binary)
          when HandshakeType::SERVER_HELLO
            key_share_entry = deserialize_keyshare_sh(binary)
          when HandshakeType::HELLO_RETRY_REQUEST
            key_share_entry = deserialize_keyshare_hrr(binary)
          else
            return UknownExtension.new(extension_type: ExtensionType::KEY_SHARE,
                                       extension_data: binary)
          end
          KeyShare.new(msg_type: msg_type,
                       key_share_entry: key_share_entry)
        end

        # struct {
        #     KeyShareEntry client_shares<0..2^16-1>;
        # } KeyShareClientHello;
        #
        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [Array of KeyShareEntry]
        def self.deserialize_keyshare_ch(binary)
          raise 'too short binary' if binary.nil? || binary.length < 2

          cs_len = bin2i(binary.slice(0, 2))
          key_share_entry = []
          itr = 2
          while itr < cs_len + 2
            group = binary.slice(itr, 2)
            itr += 2
            ke_len = bin2i(binary.slice(itr, 2))
            itr += 2
            key_exchange = binary.slice(itr, ke_len)
            key_share_entry << KeyShareEntry.new(group: group,
                                                 key_exchange: key_exchange)
            itr += ke_len
          end
          raise 'malformed binary' unless itr == binary.length

          key_share_entry
        end

        # struct {
        #     KeyShareEntry server_share;
        # } KeyShareServerHello;
        #
        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [Array of KeyShareEntry]
        def self.deserialize_keyshare_sh(binary)
          raise 'too short binary' if binary.nil? || binary.length < 4

          group = binary.slice(0, 2)
          ke_len = bin2i(binary.slice(2, 2))
          raise 'malformed binary' unless binary.length == ke_len + 4

          key_exchange = binary.slice(4, ke_len)
          [KeyShareEntry.new(group: group, key_exchange: key_exchange)]
        end

        # struct {
        #     NamedGroup selected_group;
        # } KeyShareHelloRetryRequest;
        #
        # @param binary [String]
        #
        # @raise [RuntimeError]
        #
        # @return [Array of KeyShareEntry]
        def self.deserialize_keyshare_hrr(binary)
          raise 'malformed binary' unless binary.length == 2

          group = binary.slice(0, 2)
          [KeyShareEntry.new(group: group)]
        end
      end

      class KeyShareEntry
        attr_reader :group
        attr_reader :key_exchange

        # @param group [TLS13::Message::Extension::NamedGroup]
        # @param key_exchange [String]
        def initialize(group: '', key_exchange: '')
          @group = group || ''
          raise 'invalid NamedGroup' unless @group.length == 2

          @key_exchange = key_exchange || ''
        end

        # @return [Boolean]
        def key_share_server_hello?
          @group.length == 2 && @key_exchange.length.positive?
        end

        # @return [Boolean]
        def key_share_hello_retry_request?
          @group.length == 2 && @key_exchange.empty?
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @group
          # HandshakeType::HELLO_RETRY_REQUEST
          # extension_data is single NamedGroup
          binary += i2uint16(@key_exchange.length) + @key_exchange \
            unless @key_exchange.empty?
          binary
        end
      end
    end
  end
end
