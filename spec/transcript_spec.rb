# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Transcript do
  context 'transcript, not including HRR,' do
    let(:transcript) do
      t = Transcript.new
      t.merge!(
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_SERVER_FINISHED),
        CF => Finished.deserialize(TESTBINARY_CLIENT_FINISHED)
      )
    end

    it 'should return valid transcript-hash' do
      expect(transcript.hash('SHA256', CF))
        .to eq TESTBINARY_CH_CF_TRANSCRIPT_HASH
    end
  end

  context 'transcript, including HRR,' do
    let(:transcript) do
      t = Transcript.new
      t.merge!(
        CH1 => ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO1),
        HRR => ServerHello.deserialize(TESTBINARY_HRR_HELLO_RETRY_REQUEST),
        CH => ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_HRR_SERVER_HELLO)
      )
    end

    it 'should return valid transcript-hash' do
      expect(transcript.hash('SHA256', SH))
        .to eq TESTBINARY_HRR_CH1_SH_TRANSCRIPT_HASH
    end
  end
end
