# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  module Refinements
    refine Integer do
      def to_uint8
        raise Error::ErrorAlerts, :internal_error \
          if negative? || self >= (1 << 8)

        chr
      end

      def to_uint16
        raise Error::ErrorAlerts, :internal_error \
          if negative? || self >= (1 << 16)

        [self].pack('n')
      end

      def to_uint24
        raise Error::ErrorAlerts, :internal_error \
          if negative? || self >= (1 << 24)

        [self].pack('N1')[1..]
      end

      def to_uint32
        raise Error::ErrorAlerts, :internal_error \
          if negative? || self >= (1 << 32)

        [self].pack('N1')
      end

      def to_uint64
        raise Error::ErrorAlerts, :internal_error \
          if negative? || self >= (1 << 64)

        [self >> 32, self].pack('N2')
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

    refine OpenSSL::X509::Certificate do
      def ocsp_uris
        aia = cert.extensions.find { |ex| ex.oid == 'authorityInfoAccess' }
        return nil if aia.nil?

        ostr = OpenSSL::ASN1.decode(aia.to_der).value.last
        ocsp = OpenSSL::ASN1.decode(ostr.value)
                            .map(&:value)
                            .select { |des| des.first.value == 'OCSP' }
        ocsp&.map { |o| o[1].value }
      end
    end
  end

  module Convert
    class << self
      def bin2i(binary)
        OpenSSL::BN.new(binary, 2).to_i
      end
    end
  end
end
