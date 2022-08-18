# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module SslKeyLogFile
    module Label
      CLIENT_EARLY_TRAFFIC_SECRET     = 'CLIENT_EARLY_TRAFFIC_SECRET'
      CLIENT_HANDSHAKE_TRAFFIC_SECRET = 'CLIENT_HANDSHAKE_TRAFFIC_SECRET'
      SERVER_HANDSHAKE_TRAFFIC_SECRET = 'SERVER_HANDSHAKE_TRAFFIC_SECRET'
      CLIENT_TRAFFIC_SECRET_0         = 'CLIENT_TRAFFIC_SECRET_0'
      SERVER_TRAFFIC_SECRET_0         = 'SERVER_TRAFFIC_SECRET_0'
    end

    class Writer
      # @param path [String]
      #
      # @raise [SystemCallError]
      def initialize(path)
        @file = File.new(path, 'a+')
      end

      # @param client_random [String]
      # @param secret [String]
      def write_client_early_traffic_secret(client_random, secret)
        write_key_log(
          Label::CLIENT_EARLY_TRAFFIC_SECRET,
          client_random,
          secret
        )
      end

      # @param client_random [String]
      # @param secret [String]
      def write_client_handshake_traffic_secret(client_random, secret)
        write_key_log(
          Label::CLIENT_HANDSHAKE_TRAFFIC_SECRET,
          client_random,
          secret
        )
      end

      # @param client_random [String]
      # @param secret [String]
      def write_server_handshake_traffic_secret(client_random, secret)
        write_key_log(
          Label::SERVER_HANDSHAKE_TRAFFIC_SECRET,
          client_random,
          secret
        )
      end

      # @param client_random [String]
      # @param secret [String]
      def write_client_traffic_secret_0(client_random, secret)
        write_key_log(
          Label::CLIENT_TRAFFIC_SECRET_0,
          client_random,
          secret
        )
      end

      # @param client_random [String]
      # @param secret [String]
      def write_server_traffic_secret_0(client_random, secret)
        write_key_log(
          Label::SERVER_TRAFFIC_SECRET_0,
          client_random,
          secret
        )
      end

      def close
        @file&.close
      end

      private

      # @param label [TTTLS13::SslKeyLogFile::Label]
      # @param client_random [String]
      # @param secret [String]
      def write_key_log(label, client_random, secret)
        s = "#{label} #{client_random.unpack1('H*')} #{secret.unpack1('H*')}\n"
        @file&.print(s)
      end
    end
  end
end
