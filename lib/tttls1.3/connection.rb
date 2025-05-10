# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  INITIAL = 0
  EOF     = -1

  # rubocop: disable Metrics/ClassLength
  class Connection
    include Logging

    attr_accessor :state, :ap_wcipher, :ap_rcipher, :alert_wcipher

    # @param socket [Socket]
    # @param side [:client or :server]
    def initialize(socket, side)
      @socket = socket
      @side = side
      @state = INITIAL
      @ap_wcipher = Cryptograph::Passer.new
      @ap_rcipher = Cryptograph::Passer.new
      @alert_wcipher = Cryptograph::Passer.new
      @message_queue = [] # Array of [TTTLS13::Message::$Object, String]
      @binary_buffer = '' # deposit Record.surplus_binary
      @send_record_size = Message::DEFAULT_RECORD_SIZE_LIMIT
      @recv_record_size = Message::DEFAULT_RECORD_SIZE_LIMIT
    end

    # @param nst_process [Method]
    #
    # @raise [TTTLS13::Error::ConfigError]
    #
    # @return [String]
    def read(nst_process)
      # secure channel has not established yet
      raise Error::ConfigError \
        unless (@side == :client && @state == ClientState::CONNECTED) ||
               (@side == :server && @state == ServerState::CONNECTED)
      return '' if @state == EOF

      message = nil
      loop do
        message, = recv_message(receivable_ccs: false, cipher: @ap_rcipher)
        # At any time after the server has received the client Finished
        # message, it MAY send a NewSessionTicket message.
        break unless message.is_a?(Message::NewSessionTicket)

        terminate(:unexpected_message) if @side == :server

        nst_process.call(message)
      end
      return '' if message.nil?

      message.fragment
    end

    # @return [Boolean]
    def eof?
      @state == EOF
    end

    # @param binary [String]
    #
    # @raise [TTTLS13::Error::ConfigError]
    def write(binary)
      # secure channel has not established yet
      raise Error::ConfigError \
        unless (@side == :client && @state == ClientState::CONNECTED) ||
               (@side == :server && @state == ServerState::CONNECTED)

      ap = Message::ApplicationData.new(binary)
      send_application_data(ap, @ap_wcipher)
    end

    def close
      return if @state == EOF

      send_alert(:close_notify)
      @state = EOF
    end

    # @param type [TTTLS13::Message::ContentType]
    # @param messages [Array of TTTLS13::Message::$Object] handshake messages
    # @param cipher [TTTLS13::Cryptograph::Aead, Passer]
    def send_handshakes(type, messages, cipher)
      record = Message::Record.new(
        type:,
        messages:,
        cipher:
      )
      send_record(record)
    end

    def send_ccs
      ccs_record = Message::Record.new(
        type: Message::ContentType::CCS,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [Message::ChangeCipherSpec.new],
        cipher: Cryptograph::Passer.new
      )
      send_record(ccs_record)
    end

    # @param message [TTTLS13::Message::ApplicationData]
    # @param cipher [TTTLS13::Cryptograph::Aead]
    def send_application_data(message, cipher)
      ap_record = Message::Record.new(
        type: Message::ContentType::APPLICATION_DATA,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [message],
        cipher:
      )
      send_record(ap_record)
    end

    # @param symbol [Symbol] key of ALERT_DESCRIPTION
    def send_alert(symbol)
      message = Message::Alert.new(
        description: Message::ALERT_DESCRIPTION[symbol]
      )
      type = Message::ContentType::ALERT
      type = Message::ContentType::APPLICATION_DATA \
        if @alert_wcipher.is_a?(Cryptograph::Aead)
      alert_record = Message::Record.new(
        type:,
        legacy_record_version: Message::ProtocolVersion::TLS_1_2,
        messages: [message],
        cipher: @alert_wcipher
      )
      send_record(alert_record)
    end

    # @param record [TTTLS13::Message::Record]
    def send_record(record)
      logger.info(Convert.obj2html(record))
      @socket.write(record.serialize(@send_record_size))
    end

    # @param receivable_ccs [Boolean]
    # @param cipher [TTTLS13::Cryptograph::Aead, Passer]
    #
    # @raise [TTTLS13::Error::ErrorAlerts
    #
    # @return [TTTLS13::Message::$Object]
    # @return [String]
    def recv_message(receivable_ccs:, cipher:)
      return @message_queue.shift unless @message_queue.empty?

      messages = nil
      orig_msgs = []
      loop do
        record, orig_msgs = recv_record(cipher)
        case record.type
        when Message::ContentType::HANDSHAKE,
             Message::ContentType::APPLICATION_DATA
          messages = record.messages
          break unless messages.empty?
        when Message::ContentType::CCS
          terminate(:unexpected_message) unless receivable_ccs
          next
        when Message::ContentType::ALERT
          handle_received_alert(record.messages.first)
          return nil
        else
          terminate(:unexpected_message)
        end
      end

      @message_queue += messages[1..].zip(orig_msgs[1..])
      message = messages.first
      orig_msg = orig_msgs.first
      if message.is_a?(Message::Alert)
        handle_received_alert(message)
        return nil
      end

      [message, orig_msg]
    end

    # @param cipher [TTTLS13::Cryptograph::Aead, Passer]
    #
    # @return [TTTLS13::Message::Record]
    # @return [Array of String]
    def recv_record(cipher)
      binary = @socket.read(5)
      record_len = Convert.bin2i(binary.slice(3, 2))
      binary += @socket.read(record_len)

      begin
        buffer = @binary_buffer
        record, orig_msgs, surplus_binary = Message::Record.deserialize(
          binary,
          cipher,
          buffer,
          @recv_record_size
        )
        @binary_buffer = surplus_binary
      rescue Error::ErrorAlerts => e
        terminate(e.message.to_sym)
      end

      # Received a protected ccs, peer MUST abort the handshake.
      if record.type == Message::ContentType::APPLICATION_DATA &&
         record.messages.any? { |m| m.is_a?(Message::ChangeCipherSpec) }
        terminate(:unexpected_message)
      end

      logger.info(Convert.obj2html(record))
      [record, orig_msgs]
    end

    # @param symbol [Symbol] key of ALERT_DESCRIPTION
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    def terminate(symbol)
      send_alert(symbol)
      raise Error::ErrorAlerts, symbol
    end

    # @param alert [TTTLS13::Message::Alert]
    #
    # @raise [TTTLS13::Error::ErrorAlerts]
    def handle_received_alert(alert)
      unless alert.description == Message::ALERT_DESCRIPTION[:close_notify] ||
             alert.description == Message::ALERT_DESCRIPTION[:user_canceled]
        raise alert.to_error
      end

      @state = EOF
    end
  end
  # rubocop: enable Metrics/ClassLength
end
