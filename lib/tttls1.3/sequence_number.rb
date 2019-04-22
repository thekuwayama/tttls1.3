# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  using Refinements
  class SequenceNumber
    def initialize
      @seq_num = 0
    end

    # @param str [String]
    # @param iv_len [Integer]
    #
    # @return [String]
    def xor(str, iv_len)
      l = @seq_num.to_uint64.unpack('C*')
      l.unshift(0) while l.length < iv_len
      r = str.unpack('C*')
      l.zip(r).map { |x, y| (x ^ y).chr }.join
    end

    def succ
      @seq_num += 1
    end

    # @return [Boolean]
    def next?
      @seq_num < 2**64 - 1
    end
  end
end
