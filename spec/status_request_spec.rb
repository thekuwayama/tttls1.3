# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe StatusRequest do
  context 'default status_request' do
    let(:extension) do
      StatusRequest.new
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq "\x00\x05\x00\x05\x01\x00\x00\x00\x00"
    end
  end

  context 'valid status_request' do
    let(:extension) do
      StatusRequest.new(responder_id_list: [], request_extensions: [])
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq "\x00\x05\x00\x05\x01\x00\x00\x00\x00"
    end
  end

  context 'valid status_request, 0 length request ' do
    let(:extension) do
      StatusRequest.new(responder_id_list: nil, request_extensions: nil)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end

    it 'should be serialized' do
      expect(extension.serialize).to eq "\x00\x05\x00\x05\x01\x00\x00\x00\x00"
    end
  end

  context 'valid status_request binary' do
    let(:extension) do
      StatusRequest.deserialize(TESTBINARY_STATUS_REQUEST)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::STATUS_REQUEST \
               + TESTBINARY_STATUS_REQUEST.prefix_uint16_length
    end
  end
end
