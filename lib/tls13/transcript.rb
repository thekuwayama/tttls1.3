# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  CH1  = 0
  HRR  = 1
  CH   = 2
  SH   = 3
  EE   = 4
  CR   = 5
  CT   = 6
  CV   = 7
  SF   = 8
  EOED = 9
  CCT  = 10
  CCV  = 11
  CF   = 12

  class Transcript < Hash
    def initialize
      super
    end

    # @param digest [String] name of digest algorithm
    # @param range [Range]
    #
    # @raise [TLS13::Error::TLSError]
    #
    # @return [String]
    def hash(digest, range)
      # TODO: HRR
      messages = range.to_a.map do |m|
        key?(m) ? self[m].serialize : ''
      end
      OpenSSL::Digest.digest(digest, messages.join)
    end
  end
end
