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
    def initialize(socket, _settings)
      super(socket)

      @endpoint = :server
    end

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
    # rubocop: disable Lint/EmptyWhen
    def accept
      @state = ServerState::START
      loop do
        case @state
        when ServerState::START
        when ServerState::RECVD_CH
        when ServerState::NEGOTIATED
        when ServerState::WAIT_EOED
        when ServerState::WAIT_FLIGHT2
        when ServerState::WAIT_CERT
        when ServerState::WAIT_CV
        when ServerState::WAIT_FINISHED
        when ServerState::CONNECTED
          break
        end
      end
    end
    # rubocop: enable Metrics/CyclomaticComplexity
    # rubocop: enable Lint/EmptyWhen
  end
end
