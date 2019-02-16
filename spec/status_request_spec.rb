require 'spec_helper'

RSpec.describe StatusRequest do
  context 'valid status_request, default request' do
    let(:extension) do
      StatusRequest.new
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 5
      expect(extension.request.keys).to include CertificateStatusType::OCSP
      expect(extension.request[CertificateStatusType::OCSP][0]).to eq []
      expect(extension.request[CertificateStatusType::OCSP][1]).to eq []
    end

    it 'should serialize' do
      expect(extension.serialize).to eq [0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
                                         0x00, 0x00, 0x00]
    end
  end

  context 'valid status_request' do
    let(:extension) do
      StatusRequest.new(
        request: { CertificateStatusType::OCSP => [[], []] }
      )
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 5
      expect(extension.request.keys).to include CertificateStatusType::OCSP
      expect(extension.request[CertificateStatusType::OCSP][0]).to eq []
      expect(extension.request[CertificateStatusType::OCSP][1]).to eq []
    end

    it 'should serialize' do
      expect(extension.serialize).to eq [0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
                                         0x00, 0x00, 0x00]
    end
  end

  context 'valid status_request, 0 length request ' do
    let(:extension) do
      StatusRequest.new(request: nil)
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 0
      expect(extension.request).to be_empty
    end

    it 'should serialize' do
      expect(extension.serialize).to eq [0x00, 0x05, 0x00, 0x00]
    end
  end

  context 'valid status_request binary' do
    let(:extension) do
      StatusRequest.deserialize(TESTBINARY_STATUS_REQUEST)
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 5
      expect(extension.request.keys).to include CertificateStatusType::OCSP
      expect(extension.request[CertificateStatusType::OCSP][0]).to eq []
      expect(extension.request[CertificateStatusType::OCSP][1]).to eq []
    end
  end

  context 'valid status_request binary, empty' do
    let(:extension) do
      StatusRequest.deserialize([])
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 0
      expect(extension.request).to be_empty
    end
  end

  context 'valid status_request binary, nil' do
    let(:extension) do
      StatusRequest.deserialize(nil)
    end

    it 'should generate valid status_request' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.length).to eq 0
      expect(extension.request).to be_empty
    end
  end
end
