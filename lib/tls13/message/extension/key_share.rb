# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Message
    module Extension
      class KeyShare
        attr_reader   :extension_type
        attr_accessor :msg_type
        attr_accessor :key_share_entry

        # @param msg_type [TLS13::Message::ContentType]
        # @param key_share_entry [Array of KeyShareEntry]
        #
        # @raise [RuntimeError]
        def initialize(msg_type: nil,
                       key_share_entry: [])
          @extension_type = ExtensionType::KEY_SHARE
          @msg_type = msg_type
          raise 'invalid msg_type' \
            if @msg_type != HandshakeType::CLIENT_HELLO \
               && @msg_type != HandshakeType::SERVER_HELLO \
               && @msg_type != HandshakeType::HELLO_RETRY_REQUEST

          @key_share_entry = key_share_entry || []
        end

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
            raise 'unexpected msg_type'
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
            raise 'unexpected msg_type'
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
            kse_len = bin2i(binary.slice(0, 2))
            key_share_entry = deserialize_keyshare_ch(binary.slice(2, kse_len))
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
          key_share_entry = []
          itr = 0
          while itr < binary.length
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
        attr_accessor :group
        attr_accessor :key_exchange

        # @param group [TLS13::Message::Extension::NamedGroup]
        # @param key_exchange [String]
        def initialize(group: '', key_exchange: '')
          @group = group || ''
          @key_exchange = key_exchange || ''
          # TODO: check len(key_exchange) for group
        end

        # @return [String]
        def serialize
          binary = ''
          # @msg_type == HandshakeType::HELLO_RETRY_REQUEST
          # extension_data is single NamedGroup
          binary += @group
          binary += i2uint16(@key_exchange.length) + @key_exchange
          binary
        end
      end
    end
  end
end
