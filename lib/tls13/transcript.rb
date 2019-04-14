# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  using Refinements

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
    # @param end_index [Integer]
    #
    # @return [String]
    def hash(digest, end_index)
      prefix = ''
      if key?(HRR)
        # as an exception to the general rule
        prefix = Message::HandshakeType::MESSAGE_HASH \
                 + "\x00\x00" \
                 + OpenSSL::Digest.new(digest).digest_length.to_uint8 \
                 + OpenSSL::Digest.digest(digest, self[CH1].serialize)
      end

      messages = (0..end_index).to_a.reject { |m| m == CH1 }.map do |m|
        key?(m) ? self[m].serialize : ''
      end
      s = prefix + messages.join
      OpenSSL::Digest.digest(digest, s)
    end
  end
end
