# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe OCSPStatusRequest do
  context 'default OCSPStatusRequest' do
    let(:extension) do
      OCSPStatusRequest.new
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

  context 'valid OCSPStatusRequest' do
    let(:extension) do
      OCSPStatusRequest.new(responder_id_list: [], request_extensions: [])
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

  context 'valid OCSPStatusRequest, 0 length request ' do
    let(:extension) do
      OCSPStatusRequest.new(responder_id_list: nil, request_extensions: nil)
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

  context 'valid OCSPStatusRequest binary' do
    let(:extension) do
      OCSPStatusRequest.deserialize(TESTBINARY_OCSP_STATUS_REQUEST)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.responder_id_list).to be_empty
      expect(extension.request_extensions).to be_empty
    end

    it 'should generate serializable object' do
      expect(extension.serialize)
        .to eq ExtensionType::STATUS_REQUEST \
               + TESTBINARY_OCSP_STATUS_REQUEST.prefix_uint16_length
    end
  end
end

RSpec.describe OCSPResponse do
  context 'valid OCSPResponse whose status is good' do
    let(:basic_resp) do
      server_crt = OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsa.crt')
      )
      ca_crt = OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_ca.crt')
      )
      ocsp_crt = OpenSSL::X509::Certificate.new(
        File.read(__dir__ + '/fixtures/rsa_rsa_ocsp.crt')
      )
      ocsp_key = OpenSSL::PKey.read(
        File.read(__dir__ + '/fixtures/rsa_rsa_ocsp.key')
      )

      br = OpenSSL::OCSP::BasicResponse.new
      cid = OpenSSL::OCSP::CertificateId.new(server_crt, ca_crt)
      br.add_status(
        cid,
        OpenSSL::OCSP::V_CERTSTATUS_GOOD,
        0,
        nil,
        Time.now,
        DateTime.now.next_day(1).to_time,
        []
      )
      br.sign(ocsp_crt, ocsp_key)
      br
    end

    let(:ocsp_response) do
      OpenSSL::OCSP::Response.create(
        OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL,
        basic_resp
      )
    end

    let(:extension) do
      OCSPResponse.new(ocsp_response)
    end

    it 'should be generated' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
      expect(extension.ocsp_response).to eq ocsp_response
    end

    it 'should be serialized' do
      binary = CertificateStatusType::OCSP \
               + ocsp_response.to_der.prefix_uint24_length

      expect(extension.serialize).to eq ExtensionType::STATUS_REQUEST \
                                        + binary.prefix_uint16_length
    end
  end

  context 'valid OCSPResponse binary' do
    let(:extension) do
      OCSPResponse.deserialize(TESTBINARY_OCSP_RESPONSE)
    end

    it 'should generate valid object' do
      expect(extension.extension_type).to eq ExtensionType::STATUS_REQUEST
    end
  end
end
