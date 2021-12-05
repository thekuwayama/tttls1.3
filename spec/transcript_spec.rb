# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe Transcript do
  context 'transcript, not including HRR,' do
    let(:transcript) do
      ch = ClientHello.deserialize(TESTBINARY_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS)
      ct = Certificate.deserialize(TESTBINARY_CERTIFICATE)
      cv = CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY)
      sf = Finished.deserialize(TESTBINARY_SERVER_FINISHED)
      cf = Finished.deserialize(TESTBINARY_CLIENT_FINISHED)
      t = Transcript.new
      t.merge!(
        CH => [ch, TESTBINARY_CLIENT_HELLO],
        SH => [sh, TESTBINARY_SERVER_HELLO],
        EE => [ee, TESTBINARY_ENCRYPTED_EXTENSIONS],
        CT => [ct, TESTBINARY_CERTIFICATE],
        CV => [cv, TESTBINARY_CERTIFICATE_VERIFY],
        SF => [sf, TESTBINARY_SERVER_FINISHED],
        CF => [cf, TESTBINARY_CLIENT_FINISHED]
      )
    end

    it 'should return valid transcript-hash' do
      expect(transcript.hash('SHA256', CF))
        .to eq TESTBINARY_CH_CF_TRANSCRIPT_HASH
    end
  end

  context 'transcript, including HRR,' do
    let(:transcript) do
      ch1 = ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO1)
      hrr = ServerHello.deserialize(TESTBINARY_HRR_HELLO_RETRY_REQUEST)
      ch = ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO)
      sh = ServerHello.deserialize(TESTBINARY_HRR_SERVER_HELLO)
      ee = EncryptedExtensions.deserialize(TESTBINARY_HRR_ENCRYPTED_EXTENSIONS)
      ct = Certificate.deserialize(TESTBINARY_HRR_CERTIFICATE)
      cv = CertificateVerify.deserialize(TESTBINARY_HRR_CERTIFICATE_VERIFY)
      sf = Finished.deserialize(TESTBINARY_HRR_SERVER_FINISHED)
      cf = Finished.deserialize(TESTBINARY_HRR_CLIENT_FINISHED)
      t = Transcript.new
      t.merge!(
        CH1 => [ch1, TESTBINARY_HRR_CLIENT_HELLO1],
        HRR => [hrr, TESTBINARY_HRR_HELLO_RETRY_REQUEST],
        CH => [ch, TESTBINARY_HRR_CLIENT_HELLO],
        SH => [sh, TESTBINARY_HRR_SERVER_HELLO],
        EE => [ee, TESTBINARY_HRR_ENCRYPTED_EXTENSIONS],
        CT => [ct, TESTBINARY_HRR_CERTIFICATE],
        CV => [cv, TESTBINARY_HRR_CERTIFICATE_VERIFY],
        SF => [sf, TESTBINARY_HRR_SERVER_FINISHED],
        CF => [cf, TESTBINARY_HRR_CLIENT_FINISHED]
      )
    end

    it 'should return valid transcript-hash' do
      expect(transcript.hash('SHA256', SH))
        .to eq TESTBINARY_HRR_CH1_SH_TRANSCRIPT_HASH
      expect(transcript.hash('SHA256', CF))
        .to eq TESTBINARY_HRR_CH1_CF_TRANSCRIPT_HASH
    end
  end

  context 'transcript, Resumed 0-RTT Handshake,' do
    let(:transcript) do
      ch = ClientHello.deserialize(TESTBINARY_0_RTT_CLIENT_HELLO)
      t = Transcript.new
      t.merge!(CH => [ch, TESTBINARY_0_RTT_CLIENT_HELLO])
    end

    let(:hash_len) do
      OpenSSL::Digest.new('SHA256').digest_length
    end

    it 'should return valid transcript-hash' do
      expect(transcript.truncate_hash('SHA256', CH, hash_len + 3))
        .to eq TESTBINARY_0_RTT_BINDER_HASH
    end
  end
end
