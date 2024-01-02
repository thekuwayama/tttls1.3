# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  # rubocop: disable Metrics/ModuleLength
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

      def zeros
        if positive?
          "\x00" * self
        else
          ''
        end
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
      unless method_defined?(:ocsp_uris)
        define_method(:ocsp_uris) do
          aia = extensions.find { |ex| ex.oid == 'authorityInfoAccess' }
          return nil if aia.nil?

          ostr = OpenSSL::ASN1.decode(aia.to_der).value.last
          ocsp = OpenSSL::ASN1.decode(ostr.value)
                              .map(&:value)
                              .select { |des| des.first.value == 'OCSP' }
          ocsp&.map { |o| o[1].value }
        end
      end
    end
  end

  module Convert
    class << self
      def bin2i(binary)
        OpenSSL::BN.new(binary, 2).to_i
      end

      def obj2html(obj)
        if obj.is_a?(Numeric) || obj.is_a?(TrueClass) || obj.is_a?(FalseClass)
          obj.pretty_print_inspect
        elsif obj.is_a?(String) && obj.empty?
          ''
        elsif obj.is_a? String
          '0x' + obj.unpack1('H*')
        elsif obj.is_a? NilClass
          ''
        elsif obj.is_a? Array
          '<ul>' + obj.map { |i| '<li>' + obj2html(i) + '</li>' }.join + '</ul>'
        elsif obj.is_a? Hash
          obj.map do |k, v|
            '<details><summary>' + obj2html(k) + '</summary>' \
            + obj2html(v) \
            + '</details>'
          end.join
        elsif obj.is_a?(Object) && !obj.instance_variables.empty?
          obj.instance_variables.map do |i|
            '<details><summary>' + i[1..] + '</summary>' \
            + obj2html(obj.instance_variable_get(i)) \
            + '</details>'
          end.join
        else
          obj.class.name
        end
      end
    end
  end
  # rubocop: enable Metrics/ModuleLength
end
