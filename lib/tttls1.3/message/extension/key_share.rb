# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module Message
    module Extension
      # rubocop: disable Metrics/ClassLength
      class KeyShare
        attr_reader :extension_type
        attr_reader :msg_type
        attr_reader :key_share_entry

        # @param msg_type [TTTLS13::Message::ContentType]
        # @param key_share_entry [Array of KeyShareEntry]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        # rubocop: disable Metrics/CyclomaticComplexity
        # rubocop: disable Metrics/PerceivedComplexity
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
        # rubocop: enable Metrics/CyclomaticComplexity
        # rubocop: enable Metrics/PerceivedComplexity

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
        # rubocop: disable Metrics/CyclomaticComplexity
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

          KeyShare.new(msg_type: msg_type,
                       key_share_entry: key_share_entry)
        end
        # rubocop: enable Metrics/CyclomaticComplexity

        # @param groups [Array of TTTLS13::NamedGroup]
        #
        # @return [TTTLS13::Message::Extensions::KeyShare]
        # @return [Hash of NamedGroup => OpenSSL::PKey::EC.$Object]
        def self.gen_ch_key_share(groups)
          priv_keys = {}
          kse = groups.map do |group|
            curve = NamedGroup.curve_name(group)
            ec = OpenSSL::PKey::EC.new(curve)
            ec.generate_key!
            # store private key to do the key-exchange
            priv_keys.store(group, ec)
            KeyShareEntry.new(
              group: group,
              key_exchange: ec.public_key.to_octet_string(:uncompressed)
            )
          end

          key_share = KeyShare.new(
            msg_type: HandshakeType::CLIENT_HELLO,
            key_share_entry: kse
          )

          [key_share, priv_keys]
        end

        # @param groups [TTTLS13::NamedGroup]
        #
        # @return [TTTLS13::Message::Extensions::KeyShare]
        # @return [OpenSSL::PKey::EC.$Object]
        def self.gen_sh_key_share(group)
          curve = NamedGroup.curve_name(group)
          ec = OpenSSL::PKey::EC.new(curve)
          ec.generate_key!

          key_share = KeyShare.new(
            msg_type: HandshakeType::SERVER_HELLO,
            key_share_entry: [
              KeyShareEntry.new(
                group: group,
                key_exchange: ec.public_key.to_octet_string(:uncompressed)
              )
            ]
          )

          [key_share, ec]
        end

        # @param groups [TTTLS13::NamedGroup]
        #
        # @return [TTTLS13::Message::Extensions::KeyShare]
        def self.gen_hrr_key_share(group)
          kse = KeyShareEntry.new(group: group)
          KeyShare.new(
            msg_type: HandshakeType::HELLO_RETRY_REQUEST,
            key_share_entry: [kse]
          )
        end

        class << self
          private

          # NOTE:
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
              key_share_entry << KeyShareEntry.new(group: group,
                                                   key_exchange: key_exchange)
              itr += ke_len
            end
            return nil unless itr == binary.length

            key_share_entry
          end

          # NOTE:
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

            [KeyShareEntry.new(group: group, key_exchange: key_exchange)]
          end

          # NOTE:
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
            [KeyShareEntry.new(group: group)]
          end
        end
      end
      # rubocop: enable Metrics/ClassLength

      class KeyShareEntry
        attr_reader :group
        attr_reader :key_exchange

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
