# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  HpkeSymmetricCipherSuite = \
    ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite
  module Message
    module Extension
      module ECHClientHelloType
        OUTER = "\x00"
        INNER = "\x01"
      end

      # rubocop: disable Metrics/ClassLength
      class ECHClientHello
        attr_accessor :extension_type
        attr_accessor :type
        attr_accessor :cipher_suite
        attr_accessor :config_id
        attr_accessor :enc
        attr_accessor :payload
        attr_accessor :retry_configs

        # @param type [TTTLS13::Message::Extension::ECHClientHelloType]
        # @param cipher_suite [HpkeSymmetricCipherSuite]
        # @param config_id [Integer]
        # @param enc [String]
        # @param payload [String]
        # @param retry_configs [Array of ECHConfig]
        # rubocop: disable Metrics/ParameterLists
        def initialize(type:,
                       cipher_suite: nil,
                       config_id: nil,
                       enc: nil,
                       payload: nil,
                       retry_configs: nil)
          @extension_type = ExtensionType::ENCRYPTED_CLIENT_HELLO
          @type = type
          @cipher_suite = cipher_suite
          raise Error::ErrorAlerts, :internal_error \
            if @type == ECHClientHelloType::OUTER && \
               !@cipher_suite.is_a?(HpkeSymmetricCipherSuite)

          @config_id = config_id
          @enc = enc
          @payload = payload
          @retry_configs = retry_configs
        end
        # rubocop: enable Metrics/ParameterLists

        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [String]
        def serialize
          case @type
          when ECHClientHelloType::OUTER
            binary = @type + @cipher_suite.encode + @config_id.to_uint8 \
                     + @enc.prefix_uint16_length + @payload.prefix_uint16_length
          when ECHClientHelloType::INNER
            binary = @type
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
        # @return [TTTLS13::Message::Extensions::ECHClientHello]
        # rubocop: disable Metrics/CyclomaticComplexity
        # rubocop: disable Metrics/PerceivedComplexity
        def self.deserialize(binary, msg_type)
          raise Error::ErrorAlerts, :internal_error \
            if binary.nil? || binary.empty?

          if msg_type == HandshakeType::CLIENT_HELLO
            # NOTE:
            #     struct {
            #         ECHClientHelloType type;
            #         select (ECHClientHello.type) {
            #             case outer:
            #                 HpkeSymmetricCipherSuite cipher_suite;
            #                 uint8 config_id;
            #                 opaque enc<0..2^16-1>;
            #                 opaque payload<1..2^16-1>;
            #             case inner:
            #                 Empty;
            #         };
            #     } ECHClientHello;
            case binary[0]
            when ECHClientHelloType::OUTER
              return deserialize_outer_ech(binary[1..])
            when ECHClientHelloType::INNER
              return deserialize_inner_ech(binary[1..])
            end
          elsif msg_type == HandshakeType::SERVER_HELLO
            nil
            #     struct {
            #         opaque confirmation[8];
            #     } ECHHelloRetryRequest;
          elsif msg_type == HandshakeType::ENCRYPTED_EXTENSIONS
            return deserialize_ee_ech(binary)
          end

          raise Error::ErrorAlerts, :internal_error
        end
        # rubocop: enable Metrics/CyclomaticComplexity
        # rubocop: enable Metrics/PerceivedComplexity

        class << self
          private

          # @param binary [String]
          #
          # @raise [TTTLS13::Error::ErrorAlerts]
          #
          # @return [TTTLS13::Message::Extensions::ECHClientHello]
          def deserialize_outer_ech(binary)
            raise Error::ErrorAlerts, :internal_error \
              if binary.nil? || binary.length < 5

            kdf_id = \
              HpkeSymmetricCipherSuite::HpkeKdfId.decode(binary.slice(0, 2))
            aead_id = \
              HpkeSymmetricCipherSuite::HpkeAeadId.decode(binary.slice(2, 2))
            cs = HpkeSymmetricCipherSuite.new(kdf_id, aead_id)
            cid = Convert.bin2i(binary.slice(4, 1))
            enc_len = Convert.bin2i(binary.slice(5, 2))
            i = 7
            raise Error::ErrorAlerts, :internal_error \
              if i + enc_len > binary.length

            enc = binary.slice(i, enc_len)
            i += enc_len
            raise Error::ErrorAlerts, :internal_error \
              if i + 2 > binary.length

            payload_len = Convert.bin2i(binary.slice(i, 2))
            raise Error::ErrorAlerts, :internal_error \
              if i + payload_len > binary.length

            payload = binary.slice(i, payload_len)
            ECHClientHello.new(
              type: ECHClientHelloType::OUTER,
              cipher_suite: cs,
              config_id: cid,
              enc: enc,
              payload: payload
            )
          end

          # @param binary [String]
          #
          # @raise [TTTLS13::Error::ErrorAlerts]
          #
          # @return [TTTLS13::Message::Extensions::ECHClientHello]
          def deserialize_inner_ech(binary)
            raise Error::ErrorAlerts, :internal_error unless binary.empty?

            ECHClientHello.new(type: ECHClientHelloType::INNER)
          end

          # NOTE:
          #     struct {
          #         ECHConfigList retry_configs;
          #     } ECHEncryptedExtensions;
          #
          # @param binary [String]
          #
          # @raise [TTTLS13::Error::ErrorAlerts]
          #
          # @return [TTTLS13::Message::Extensions::ECHClientHello]
          def deserialize_ee_ech(binary)
            raise Error::ErrorAlerts, :internal_error \
              if binary.nil? ||
                 binary.length != binary.slice(0, 2).unpack1('n') + 2

            ECHClientHello.new(
              type: nil,
              retry_configs: ECHConfig.decode_vectors(binary.slice(2..))
            )
          end
        end

        # @return [TTTLS13::Message::Extensions::ECHClientHello]
        def self.new_inner
          ECHClientHello.new(type: ECHClientHelloType::INNER)
        end

        # @param cipher_suite [HpkeSymmetricCipherSuite]
        # @param config_id [Integer]
        # @param enc [String]
        # @param payload [String]
        #
        # @return [TTTLS13::Message::Extensions::ECHClientHello]
        def self.new_outer(cipher_suite:, config_id:, enc:, payload:)
          ECHClientHello.new(
            type: ECHClientHelloType::OUTER,
            cipher_suite: cipher_suite,
            config_id: config_id,
            enc: enc,
            payload: payload
          )
        end
      end
    end
  end
  # rubocop: enable Metrics/ClassLength
end
