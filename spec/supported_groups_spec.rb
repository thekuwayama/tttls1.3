require 'spec_helper'

RSpec.describe SupportedGroups do
  context 'valid supported_groups' do
    let(:extension) do
      SupportedGroups.new(
        named_group_list: [
          NamedGroup::SECP256R1,
          NamedGroup::SECP384R1,
          NamedGroup::SECP521R1,
          NamedGroup::X25519
        ]
      )
    end

    it 'should generate valid supported_groups' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_GROUPS
      expect(extension.length).to eq 10
      expect(extension.named_group_list).to eq [NamedGroup::SECP256R1,
                                                NamedGroup::SECP384R1,
                                                NamedGroup::SECP521R1,
                                                NamedGroup::X25519]
    end
  end

  context 'default supported_groups' do
    let(:extension) do
      SupportedGroups.new
    end

    it 'should generate valid supported_groups' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_GROUPS
      expect(extension.length).to eq 10
      expect(extension.named_group_list).to eq [NamedGroup::SECP256R1,
                                                NamedGroup::SECP384R1,
                                                NamedGroup::SECP521R1,
                                                NamedGroup::X25519]
    end
  end

  context 'valid supported_groups binary' do
    let(:extension) do
      SupportedGroups.deserialize(TESTBINARY_SUPPORTED_GROUPS)
    end

    it 'should generate valid supported_groups' do
      expect(extension.extension_type).to eq ExtensionType::SUPPORTED_GROUPS
      expect(extension.length).to eq 10
      expect(extension.named_group_list).to eq [NamedGroup::SECP256R1,
                                                NamedGroup::SECP384R1,
                                                NamedGroup::SECP521R1,
                                                NamedGroup::X25519]
    end
  end
end