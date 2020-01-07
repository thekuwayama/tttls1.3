# encoding: ascii-8bit
# frozen_string_literal: true

# signature_algorithms_cert.rb needs signature_algorithms.rb so that `sort`
Dir[File.dirname(__FILE__) + '/extension/*.rb'].sort.each { |f| require f }

module TTTLS13
  using Refinements
  module Message
    class Extensions < Hash
      # @param extensions [Array of TTTLS13::Message::Extension::$Object]
      #
      # @example
      #   Extensions.new([SupportedVersions.new, ServerName.new('example.com')]
      def initialize(extensions = [])
        extensions.each do |ex|
          super[ex.extension_type] = ex
        end
      end

      alias super_fetch fetch

      # NOTE:
      # "pre_shared_key" MUST be the last extension in the ClientHello
      #
      # @return [String]
      def serialize
        except_ch_psk = values.reject do |ex|
          ex.extension_type == ExtensionType::PRE_SHARED_KEY &&
            ex.msg_type == HandshakeType::CLIENT_HELLO
        end
        binary = except_ch_psk.map(&:serialize).join

        psk = super_fetch(ExtensionType::PRE_SHARED_KEY, nil)
        binary += psk.serialize if psk&.msg_type == HandshakeType::CLIENT_HELLO

        binary.prefix_uint16_length
      end

      # @param binary [String]
      # @param msg_type [TTTLS13::Message::HandshakeType]
      #
      # @raise [TTTLS13::Error::ErrorAlerts]
      #
      # @return [TTTLS13::Message::Extensions]
      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/PerceivedComplexity
      def self.deserialize(binary, msg_type)
        raise Error::ErrorAlerts, :internal_error if binary.nil?

        exs = Extensions.new
        i = 0
        while i < binary.length
          raise Error::ErrorAlerts, :decode_error if i + 4 > binary.length

          extension_type = binary.slice(i, 2)
          i += 2
          ex_len = Convert.bin2i(binary.slice(i, 2))
          i += 2

          raise Error::ErrorAlerts, :decode_error if i + ex_len > binary.length

          ex_bin = binary.slice(i, ex_len)
          ex = deserialize_extension(ex_bin, extension_type, msg_type)
          if ex.nil?
            # ignore unparsable binary, but only transcript
            ex = Extension::UnknownExtension.new(extension_type: extension_type,
                                                 extension_data: ex_bin)
          end

          # There MUST NOT be more than one extension of the same type in a
          # given extension block.
          raise Error::ErrorAlerts, :unsupported_extension \
            if exs.include?(extension_type)

          exs[extension_type] = ex
          i += ex_len
        end
        raise Error::ErrorAlerts, :decode_error unless i == binary.length

        exs
      end
      # rubocop: enable Metrics/CyclomaticComplexity
      # rubocop: enable Metrics/PerceivedComplexity

      # @param key [TTTLS13::Message::ExtensionType]
      # @param default
      #
      # @return [TTTLS13::Message::Extension::$Object]
      def fetch(key, default = nil)
        return nil if super_fetch(key, nil).is_a?(Extension::UnknownExtension)

        super_fetch(key, default)
      end

      def [](key)
        fetch(key)
      end

      # @param ex [TTTLS13::Message::Extension::$Object]
      #
      # @return [TTTLS13::Message::Extension::$Object]
      def <<(ex)
        store(ex.extension_type, ex)
      end

      class << self
        private

        # NOTE:
        # deserialize_extension ignores unparsable extension.
        # Received unparsable binary, returns nil, doesn't raise
        # ErrorAlerts :decode_error.
        #
        # @param binary [String]
        # @param extension_type [TTTLS13::Message::ExtensionType]
        # @param msg_type [TTTLS13::Message::HandshakeType]
        #
        # @raise [TTTLS13::Error::ErrorAlerts]
        #
        # @return [TTTLS13::Message::Extension::$Object, nil]
        # rubocop: disable Metrics/CyclomaticComplexity
        # rubocop: disable Metrics/MethodLength
        def deserialize_extension(binary, extension_type, msg_type)
          raise Error::ErrorAlerts, :internal_error if binary.nil?

          case extension_type
          when ExtensionType::SERVER_NAME
            Extension::ServerName.deserialize(binary)
          when ExtensionType::STATUS_REQUEST
            if msg_type == HandshakeType::CLIENT_HELLO
              return Extension::OCSPStatusRequest.deserialize(binary)
            end

            if msg_type == HandshakeType::CERTIFICATE
              return Extension::OCSPResponse.deserialize(binary)
            end

            Extension::UnknownExtension.deserialize(binary, extension_type)
          when ExtensionType::SUPPORTED_GROUPS
            Extension::SupportedGroups.deserialize(binary)
          when ExtensionType::SIGNATURE_ALGORITHMS
            Extension::SignatureAlgorithms.deserialize(binary)
          when ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            Extension::Alpn.deserialize(binary)
          when ExtensionType::RECORD_SIZE_LIMIT
            Extension::RecordSizeLimit.deserialize(binary)
          when ExtensionType::PRE_SHARED_KEY
            Extension::PreSharedKey.deserialize(binary, msg_type)
          when ExtensionType::EARLY_DATA
            Extension::EarlyDataIndication.deserialize(binary, msg_type)
          when ExtensionType::SUPPORTED_VERSIONS
            Extension::SupportedVersions.deserialize(binary, msg_type)
          when ExtensionType::COOKIE
            Extension::Cookie.deserialize(binary)
          when ExtensionType::PSK_KEY_EXCHANGE_MODES
            Extension::PskKeyExchangeModes.deserialize(binary)
          when ExtensionType::SIGNATURE_ALGORITHMS_CERT
            Extension::SignatureAlgorithmsCert.deserialize(binary)
          when ExtensionType::KEY_SHARE
            Extension::KeyShare.deserialize(binary, msg_type)
          else
            Extension::UnknownExtension.deserialize(binary, extension_type)
          end
        end
        # rubocop: enable Metrics/CyclomaticComplexity
        # rubocop: enable Metrics/MethodLength
      end
    end
  end
end
