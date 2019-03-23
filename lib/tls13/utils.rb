# encoding: ascii-8bit
# frozen_string_literal: true

def i2uint8(int)
  raise 'invalid argument' if int.negative? || int >= (1 << 8)

  int.chr
end

def i2uint16(int)
  raise 'invalid argument' if int.negative? || int >= (1 << 16)

  [
    int / (1 << 8),
    int % (1 << 8)
  ].map(&:chr).join
end

def i2uint24(int)
  raise 'invalid argument' if int.negative? || int >= (1 << 24)

  [
    int / (1 << 16),
    int % (1 << 16) / (1 << 8),
    int % (1 << 8)
  ].map(&:chr).join
end

def i2uint32(int)
  raise 'invalid argument' if int.negative? || int >= (1 << 32)

  [
    int / (1 << 24),
    int % (1 << 24) / (1 << 16),
    int % (1 << 16) / (1 << 8),
    int % (1 << 8)
  ].map(&:chr).join
end

def i2uint64(int)
  raise 'invalid argument' if int.negative? || int >= (1 << 64)

  [
    int / (1 << 32),
    int % (1 << 32) / (1 << 24),
    int % (1 << 24) / (1 << 16),
    int % (1 << 16) / (1 << 8),
    int % (1 << 8)
  ].map(&:chr).join
end

def bin2i(binary)
  binary.bytes.reverse.map.with_index { |x, i| x << 8 * i }.sum
end

def uint8_length_prefix(opaque)
  i2uint8(opaque.length) + opaque
end

def uint16_length_prefix(opaque)
  i2uint16(opaque.length) + opaque
end

def uint24_length_prefix(opaque)
  i2uint24(opaque.length) + opaque
end

def uint32_length_prefix(opaque)
  i2uint32(opaque.length) + opaque
end

def uint64_length_prefix(opaque)
  i2uint64(opaque.length) + opaque
end

def xor(lstr, rstr, len)
  l = lstr.unpack('C*')
  l.unshift(0) while l.length < len
  r = rstr.unpack('C*')
  r.unshift(0) while r.length < len
  l.zip(r).map { |x, y| (x ^ y).chr }.join
end
