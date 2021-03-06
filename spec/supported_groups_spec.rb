# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe SupportedGroups do
  context 'valid supported_groups' do
    let(:named_group_list) do
      [NamedGroup::SECP256R1,
       NamedGroup::SECP384R1]
    end

    let(:extension) do
      SupportedGroups.new(named_group_list)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_GROUPS
      expect(extension.named_group_list).to eq named_group_list
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq ExtensionType::SUPPORTED_GROUPS \
                                        + 6.to_uint16 \
                                        + 4.to_uint16 \
                                        + named_group_list.join
    end
  end

  context 'invalid supported_groups, empty,' do
    let(:extension) do
      SupportedGroups.new([])
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'invalid supported_groups, too long,' do
    let(:extension) do
      SupportedGroups.new((0..2**15 - 1).to_a.map(&:to_uint16))
    end

    it 'should not be generated' do
      expect { extension }.to raise_error(ErrorAlerts)
    end
  end

  context 'valid supported_groups binary' do
    let(:extension) do
      SupportedGroups.deserialize(TESTBINARY_SUPPORTED_GROUPS)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_GROUPS
      expect(extension.named_group_list).to eq [NamedGroup::SECP256R1,
                                                NamedGroup::SECP384R1,
                                                NamedGroup::SECP521R1]
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::SUPPORTED_GROUPS \
               + TESTBINARY_SUPPORTED_GROUPS.prefix_uint16_length
    end
  end

  context 'invalid supported_groups binary, malformed binary,' do
    let(:extension) do
      SupportedGroups.deserialize(TESTBINARY_SUPPORTED_GROUPS[0...-1])
    end

    it 'should return nil' do
      expect(extension).to be nil
    end
  end
end
