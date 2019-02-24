# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  class Connection
    attr_reader :state
    attr_reader :security_parameters
    attr_reader :socket
    attr_reader :handshake_hash

    def initialize(**settings)
      # TODO
    end

    def read
      # TODO
    end

    def write(data)
      # TODO
    end
  end
end
