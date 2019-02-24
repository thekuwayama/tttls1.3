# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ServerName do
  context 'valid server_name' do
    let(:extension) do
      ServerName.new('example.com')
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::SERVER_NAME
      expect(extension.length).to eq 16
      expect(extension.server_name).to eq 'example.com'
    end
  end

  context 'valid server_name binary' do
    let(:extension) do
      ServerName.deserialize(TESTBINARY_SERVER_NAME)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::SERVER_NAME
      expect(extension.length).to eq 15
      expect(extension.server_name).to eq 'github.com'
    end
  end
end
