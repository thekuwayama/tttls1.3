def i2uint16(int)
  raise 'invalid argument' if int < 0 || int >= (1 << 16)

  [int / (1 << 8), int % (1 << 8)]
end

def i2uint24(int)
  raise 'invalid argument' if int < 0 || int >= (1 << 24)

  [int / (1 << 16), int / (1 << 8), int % (1 << 8)]
end

def arr2i(array)
  array.reverse.map.with_index { |x, i| x << 8 * i }.sum
end
