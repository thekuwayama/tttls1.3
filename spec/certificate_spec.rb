# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'
using Refinements

RSpec.describe Certificate do
  context 'valid certificate' do
    let(:certificate) do
      OpenSSL::X509::Certificate.new(File.read(__dir__ + '/../tmp/server.crt'))
    end

    let(:message) do
      Certificate.new(certificate_list: [CertificateEntry.new(certificate)])
    end

    it 'should be generated' do
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE
      expect(message.certificate_request_context).to be_empty

      certificate_entry = message.certificate_list.first
      expect(certificate_entry.cert_data.subject.to_s).to eq '/CN=test-server'
      expect(certificate_entry.extensions).to be_empty
    end

    it 'should be serialized' do
      expect(message.serialize).to eq HandshakeType::CERTIFICATE \
                                      + 994.to_uint24 \
                                      + 0.to_uint8 \
                                      + 990.to_uint24 \
                                      + 985.to_uint24 \
                                      + certificate.to_der \
                                      + 0.to_uint16
    end
  end

  context 'valid certificate binary' do
    let(:message) do
      Certificate.deserialize(TESTBINARY_CERTIFICATE)
    end

    it 'should generate valid object' do
      expect(message.msg_type).to eq HandshakeType::CERTIFICATE
      expect(message.certificate_request_context).to be_empty

      certificate_entry = message.certificate_list.first
      expect(certificate_entry.cert_data.subject.to_s).to eq '/CN=rsa'
      expect(certificate_entry.extensions).to be_empty
    end

    it 'should generate serializable object' do
      expect(message.serialize).to eq TESTBINARY_CERTIFICATE
    end
  end
end
