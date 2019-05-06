# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  module ServerState
    # initial value is 0, eof value is -1
    START         = 1
    RECVD_CH      = 2
    NEGOTIATED    = 3
    WAIT_EOED     = 4
    WAIT_FLIGHT2  = 5
    WAIT_CERT     = 6
    WAIT_CV       = 7
    WAIT_FINISHED = 8
    CONNECTED     = 9
  end

  class Server < Connection
    # @param socket [Socket]
    # @param settings [Hash]
    # rubocop: disable Lint/UnusedMethodArgument
    def initialize(socket, **settings)
      super(socket)

      @endpoint = :server
    end
    # rubocop: enable Lint/UnusedMethodArgument

    # NOTE:
    #                              START <-----+
    #               Recv ClientHello |         | Send HelloRetryRequest
    #                                v         |
    #                             RECVD_CH ----+
    #                                | Select parameters
    #                                v
    #                             NEGOTIATED
    #                                | Send ServerHello
    #                                | K_send = handshake
    #                                | Send EncryptedExtensions
    #                                | [Send CertificateRequest]
    # Can send                       | [Send Certificate + CertificateVerify]
    # app data                       | Send Finished
    # after   -->                    | K_send = application
    # here                  +--------+--------+
    #              No 0-RTT |                 | 0-RTT
    #                       |                 |
    #   K_recv = handshake  |                 | K_recv = early data
    # [Skip decrypt errors] |    +------> WAIT_EOED -+
    #                       |    |       Recv |      | Recv EndOfEarlyData
    #                       |    | early data |      | K_recv = handshake
    #                       |    +------------+      |
    #                       |                        |
    #                       +> WAIT_FLIGHT2 <--------+
    #                                |
    #                       +--------+--------+
    #               No auth |                 | Client auth
    #                       |                 |
    #                       |                 v
    #                       |             WAIT_CERT
    #                       |        Recv |       | Recv Certificate
    #                       |       empty |       v
    #                       | Certificate |    WAIT_CV
    #                       |             |       | Recv
    #                       |             v       | CertificateVerify
    #                       +-> WAIT_FINISHED <---+
    #                                | Recv Finished
    #                                | K_recv = application
    #                                v
    #                            CONNECTED
    #
    # https://tools.ietf.org/html/rfc8446#appendix-A.2
    #
    # rubocop: disable Metrics/CyclomaticComplexity
    def accept
      @state = ServerState::START
      loop do
        case @state
        when ServerState::START
          logger.debug('ServerState::START')

          recv_client_hello
          @state = ServerState::RECVD_CH
        when ServerState::RECVD_CH
          logger.debug('ServerState::RECVD_CH')
        when ServerState::NEGOTIATED
          logger.debug('ServerState::NEGOTIATED')
        when ServerState::WAIT_EOED
          logger.debug('ServerState::WAIT_EOED')
        when ServerState::WAIT_FLIGHT2
          logger.debug('ServerState::WAIT_FLIGHT2')
        when ServerState::WAIT_CERT
          logger.debug('ServerState::WAIT_CERT')
        when ServerState::WAIT_CV
          logger.debug('ServerState::WAIT_CV')
        when ServerState::WAIT_FINISHED
          logger.debug('ServerState::WAIT_FINISHED')

          recv_finished
          @state = ServerState::CONNECTED
        when ServerState::CONNECTED
          logger.debug('ServerState::CONNECTED')
          break
        end
      end
    end
    # rubocop: enable Metrics/CyclomaticComplexity

    private

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::ClientHello]
    def recv_client_hello
      ch = recv_message
      terminate(:unexpected_message) unless ch.is_a?(Message::ClientHello)

      @transcript[CH] = ch
    end

    # @raise [TTTLS13::Error::ErrorAlerts]
    #
    # @return [TTTLS13::Message::Finished]
    def recv_finished
      cf = recv_message
      terminate(:unexpected_message) unless cf.is_a?(Message::Finished)

      @transcript[CF] = cf
    end

    # @return [String]
    def sign_certificate_verify
      context = 'TLS 1.3, server CertificateVerify'
      do_sign_certificate_verify(private_key: @private_key,
                                 signature_scheme: @signature_scheme,
                                 context: context,
                                 handshake_context_end: CT)
    end

    # @return [String]
    def sign_finished
      digest = CipherSuite.digest(@cipher_suite)
      finished_key = @key_schedule.server_finished_key
      do_sign_finished(digest: digest,
                       finished_key: finished_key,
                       handshake_context_end: CV)
    end
  end
end
