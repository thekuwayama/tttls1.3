# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Logging
    def logger
      Logging.logger
    end

    def self.logger
      @logger ||= Logger.new($stderr, Logger::WARN)
    end
  end
end
