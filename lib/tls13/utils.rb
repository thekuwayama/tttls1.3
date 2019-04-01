# encoding: ascii-8bit
# frozen_string_literal: true

module TLS13
  module Refinements
    refine Integer do
      def to_uint8
        raise Error::InternalError if negative? || self >= (1 << 8)

        chr
      end

      def to_uint16
        raise Error::InternalError if negative? || self >= (1 << 16)

        [
          self / (1 << 8),
          self % (1 << 8)
        ].map(&:chr).join
      end

      def to_uint24
        raise Error::InternalError if negative? || self >= (1 << 24)

        [
          self / (1 << 16),
          self % (1 << 16) / (1 << 8),
          self % (1 << 8)
        ].map(&:chr).join
      end

      def to_uint32
        raise Error::InternalError if negative? || self >= (1 << 32)

        [
          self / (1 << 24),
          self % (1 << 24) / (1 << 16),
          self % (1 << 16) / (1 << 8),
          self % (1 << 8)
        ].map(&:chr).join
      end

      def to_uint64
        raise Error::InternalError if negative? || self >= (1 << 64)

        [
          self / (1 << 32),
          self % (1 << 32) / (1 << 24),
          self % (1 << 24) / (1 << 16),
          self % (1 << 16) / (1 << 8),
          self % (1 << 8)
        ].map(&:chr).join
      end
    end

    refine String do
      def prefix_uint8_length
        length.to_uint8 + self
      end

      def prefix_uint16_length
        length.to_uint16 + self
      end

      def prefix_uint24_length
        length.to_uint24 + self
      end

      def prefix_uint32_length
        length.to_uint32 + self
      end

      def prefix_uint64_length
        length.to_uint64 + self
      end
    end
  end

  module Convert
    class << self
      def bin2i(binary)
        binary.unpack('C*').reverse.map.with_index { |x, i| x << 8 * i }.sum
      end
    end
  end
end
