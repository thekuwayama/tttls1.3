# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe ECHOuterExtensions do
  context 'valid ech_outer_extensions, [key_share]' do
    let(:extension) do
      ECHOuterExtensions.new([ExtensionType::KEY_SHARE])
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::ECH_OUTER_EXTENSIONS
      expect(extension.outer_extensions).to eq [ExtensionType::KEY_SHARE]
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::ECH_OUTER_EXTENSIONS \
                                        + 3.to_uint16 \
                                        + 2.to_uint8 \
                                        + ExtensionType::KEY_SHARE
    end
  end

  context 'valid ech_outer_extensions binary' do
    let(:extension) do
      ECHOuterExtensions.deserialize(TESTBINARY_ECH_OUTER_EXTENSIONS)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to be ExtensionType::ECH_OUTER_EXTENSIONS
      expect(extension.outer_extensions).to eq [ExtensionType::KEY_SHARE]
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::ECH_OUTER_EXTENSIONS \
               + TESTBINARY_ECH_OUTER_EXTENSIONS.prefix_uint16_length
    end
  end
end
