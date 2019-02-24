require 'spec_helper'

RSpec.describe StatusRequest do
  context 'valid status_request, default request' do
    let(:extension) do
      StatusRequest.new
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 5
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end

    it 'should serialize' do
      expect(extension.serialize).to eq "\x00\x05\x00\x05\x01\x00\x00\x00\x00"
    end
  end

  context 'valid status_request' do
    let(:extension) do
      StatusRequest.new(responder_id_list: [], request_extensions: '')
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 5
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end

    it 'should serialize' do
      expect(extension.serialize).to eq "\x00\x05\x00\x05\x01\x00\x00\x00\x00"
    end
  end

  context 'valid status_request, 0 length request ' do
    let(:extension) do
      StatusRequest.new(responder_id_list: nil, request_extensions: nil)
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 5
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end

    it 'should serialize' do
      expect(extension.serialize).to eq "\x00\x05\x00\x05\x01\x00\x00\x00\x00"
    end
  end

  context 'valid status_request binary' do
    let(:extension) do
      StatusRequest.deserialize(TESTBINARY_STATUS_REQUEST)
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 5
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end
  end
end
