# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      # rubocop: disable Metrics/ClassLength
      class KeyShare
        attr_reader :extension_type, :msg_type, :key_share_entry

        # @param msg_type [TTTLS13::Message::HandshakeType]
        # @param key_share_entry [Array of KeyShareEntry]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(msg_type:, key_share_entry: [])
          @extension_type = ExtensionType::KEY_SHARE
          @msg_type = msg_type
          @key_share_entry = key_share_entry || []
          raise Error::ErrorAlerts, :internal_error \
            unless (@msg_type == HandshakeType::CLIENT_HELLO &&
                    @key_share_entry.length >= 0 &&
                    @key_share_entry.all?(&:valid_key_share_client_hello?)) ||
                   (@msg_type == HandshakeType::SERVER_HELLO &&
                    @key_share_entry.length == 1 &&
                    @key_share_entry.first.valid_key_share_server_hello?) ||
                   (@msg_type == HandshakeType::HELLO_RETRY_REQUEST &&
                    @key_share_entry.length == 1 &&
                    @key_share_entry.first.valid_key_share_hello_retry_request?)
        end

        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [String]
        def serialize
          case @msg_type
          when HandshakeType::CLIENT_HELLO
            binary = @key_share_entry.map(&:serialize).join.prefix_uint16_length
          when HandshakeType::SERVER_HELLO, HandshakeType::HELLO_RETRY_REQUEST
            binary = @key_share_entry.first.serialize
          else
            raise Error::ErrorAlerts, :internal_error
          end
          @extension_type + binary.prefix_uint16_length
        end

        # @param binary [String]
        # @param msg_type [TTTLS13::Message::HandshakeType]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extensions::KeyShare, nil]
        def self.deserialize(binary, msg_type)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          case msg_type
          when HandshakeType::CLIENT_HELLO
            key_share_entry = deserialize_keyshare_ch(binary)
            return nil \
              unless key_share_entry.all?(&:valid_key_share_client_hello?)
          when HandshakeType::SERVER_HELLO
            key_share_entry = deserialize_keyshare_sh(binary)
            return nil \
              unless key_share_entry.first.valid_key_share_server_hello?
          when HandshakeType::HELLO_RETRY_REQUEST
            key_share_entry = deserialize_keyshare_hrr(binary)
            return nil \
              unless key_share_entry.first.valid_key_share_hello_retry_request?
          else
            raise Error::ErrorAlerts, :internal_error
          end
          return nil if key_share_entry.nil?

          KeyShare.new(msg_type:,
                       key_share_entry:)
        end

        # @param groups [Array of TTTLS13::NamedGroup]
        #
        # @return [TTTLS13::Message::Extensions::KeyShare]
        # @return [TTTLS13::SharedSecret]
        def self.gen_ch_key_share(groups)
          shared_secret = SharedSecret.gen_from_named_groups(groups)
          key_share = KeyShare.new(
            msg_type: HandshakeType::CLIENT_HELLO,
            key_share_entry: shared_secret.key_share_entries
          )

          [key_share, shared_secret]
        end

        # @param group [TTTLS13::NamedGroup]
        #
        # @return [TTTLS13::Message::Extensions::KeyShare]
        # @return [TTTLS13::SharedSecret]
        def self.gen_sh_key_share(group)
          shared_secret = SharedSecret.gen_from_named_groups([group])

          key_share = KeyShare.new(
            msg_type: HandshakeType::SERVER_HELLO,
            key_share_entry: shared_secret.key_share_entries
          )

          [key_share, shared_secret]
        end

        # @param group [TTTLS13::NamedGroup]
        #
        # @return [TTTLS13::Message::Extensions::KeyShare]
        def self.gen_hrr_key_share(group)
          kse = KeyShareEntry.new(group:)
          KeyShare.new(
            msg_type: HandshakeType::HELLO_RETRY_REQUEST,
            key_share_entry: [kse]
          )
        end

        class << self
          private

          #     struct {
          #         KeyShareEntry client_shares<0..2^16-1>;
          #     } KeyShareClientHello;
          #
          # @param binary [String]
          #
          # @raise [TTTLS13::Error::ErrorAlerts]
          #
          # @return [Array of KeyShareEntry, nil]
          def deserialize_keyshare_ch(binary)
            raise Error::ErrorAlerts, :internal_error if binary.nil?

            return nil if binary.length < 2

            cs_len = Convert.bin2i(binary.slice(0, 2))
            key_share_entry = []
            itr = 2
            while itr < cs_len + 2
              return nil if itr + 4 > binary.length

              group = binary.slice(itr, 2)
              itr += 2
              ke_len = Convert.bin2i(binary.slice(itr, 2))
              itr += 2
              key_exchange = binary.slice(itr, ke_len)
              key_share_entry << KeyShareEntry.new(group:,
                                                   key_exchange:)
              itr += ke_len
            end
            return nil unless itr == binary.length

            key_share_entry
          end

          #     struct {
          #         KeyShareEntry server_share;
          #     } KeyShareServerHello;
          #
          # @param binary [String]
          #
          # @raise [TTTLS13::Error::ErrorAlerts]
          #
          # @return [Array of KeyShareEntry, nil]
          def deserialize_keyshare_sh(binary)
            raise Error::ErrorAlerts, :internal_error if binary.nil?

            return nil if binary.length < 4

            group = binary.slice(0, 2)
            ke_len = Convert.bin2i(binary.slice(2, 2))
            key_exchange = binary.slice(4, ke_len)
            return nil unless ke_len + 4 == binary.length

            [KeyShareEntry.new(group:, key_exchange:)]
          end

          #     struct {
          #         NamedGroup selected_group;
          #     } KeyShareHelloRetryRequest;
          #
          # @param binary [String]
          #
          # @raise [TTTLS13::Error::ErrorAlerts]
          #
          # @return [Array of KeyShareEntry, nil]
          def deserialize_keyshare_hrr(binary)
            raise Error::ErrorAlerts, :internal_error if binary.nil?

            return nil unless binary.length == 2

            group = binary.slice(0, 2)
            [KeyShareEntry.new(group:)]
          end
        end
      end
      # rubocop: enable Metrics/ClassLength

      class KeyShareEntry
        attr_reader :group, :key_exchange

        # @param group [TTTLS13::NamedGroup]
        # @param key_exchange [String]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        def initialize(group:, key_exchange: nil)
          @group = group || ''
          @key_exchange = key_exchange || ''
          raise Error::ErrorAlerts, :internal_error unless @group.length == 2
        end

        # @return [Boolean]
        def valid_key_share_client_hello?
          @group.length == 2 && @key_exchange.length.positive?
        end

        # @return [Boolean]
        def valid_key_share_server_hello?
          @group.length == 2 && @key_exchange.length.positive?
        end

        # @return [Boolean]
        def valid_key_share_hello_retry_request?
          @group.length == 2 && @key_exchange.empty?
        end

        # @return [String]
        def serialize
          binary = ''
          binary += @group
          # KeyShareHelloRetryRequest doesn't have key_exchange.
          binary += @key_exchange.prefix_uint16_length \
            unless @key_exchange.empty?
          binary
        end
      end
    end
  end
end
