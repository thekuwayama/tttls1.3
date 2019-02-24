def i2uint16(int)
  raise 'invalid argument' if int < 0 || int >= (1 << 16)

  [
    int / (1 << 8),
    int % (1 << 8)
  ].map(&:chr).join
end

def i2uint24(int)
  raise 'invalid argument' if int < 0 || int >= (1 << 24)

  [
    int / (1 << 16),
    int % (1 << 16) / (1 << 8),
    int % (1 << 8)
  ].map(&:chr).join
end

def i2uint32(int)
  raise 'invalid argument' if int < 0 || int >= (1 << 32)

  [
    int / (1 << 24),
    int % (1 << 24) / (1 << 16),
    int % (1 << 16) / (1 << 8),
    int % (1 << 8)
  ].map(&:chr).join
end

def bin2i(binary)
  binary.bytes.reverse.map.with_index { |x, i| x << 8 * i }.sum
end
