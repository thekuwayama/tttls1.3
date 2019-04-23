# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KeySchedule do
  context 'key_schedule, Simple 1-RTT Handshake,' do
    let(:key_schedule) do
      transcript = Transcript.new
      transcript.merge!(
        CH => ClientHello.deserialize(TESTBINARY_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_SERVER_HELLO),
        EE => EncryptedExtensions.deserialize(TESTBINARY_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_SERVER_FINISHED),
        CF => Finished.deserialize(TESTBINARY_CLIENT_FINISHED)
      )
      KeySchedule.new(shared_secret: TESTBINARY_SHARED_SECRET,
                      cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
                      transcript: transcript)
    end

    it 'should generate secret' do
      expect(key_schedule.client_handshake_traffic_secret)
        .to eq TESTBINARY_C_HS_TRAFFIC
      expect(key_schedule.server_handshake_traffic_secret)
        .to eq TESTBINARY_S_HS_TRAFFIC
      expect(key_schedule.client_application_traffic_secret)
        .to eq TESTBINARY_C_AP_TRAFFIC
      expect(key_schedule.server_application_traffic_secret)
        .to eq TESTBINARY_S_AP_TRAFFIC
      expect(key_schedule.exporter_master_secret)
        .to eq TESTBINARY_EXP_MASTER
      expect(key_schedule.resumption_master_secret)
        .to eq TESTBINARY_RES_MASTER
    end

    it 'should generate server finished_key' do
      expect(key_schedule.server_finished_key)
        .to eq TESTBINARY_SERVER_FINISHED_KEY
    end

    it 'should generate server parameters write_key, iv' do
      expect(key_schedule.server_handshake_write_key)
        .to eq TESTBINARY_SERVER_PARAMETERS_WRITE_KEY
      expect(key_schedule.server_handshake_write_iv)
        .to eq TESTBINARY_SERVER_PARAMETERS_WRITE_IV
    end

    it 'should generate client finished_key' do
      expect(key_schedule.client_finished_key)
        .to eq TESTBINARY_CLIENT_FINISHED_KEY
    end

    it 'should generate client finished write_key, iv' do
      expect(key_schedule.client_handshake_write_key)
        .to eq TESTBINARY_CLIENT_FINISHED_WRITE_KEY
      expect(key_schedule.client_handshake_write_iv)
        .to eq TESTBINARY_CLIENT_FINISHED_WRITE_IV
    end

    it 'should generete server application write_key, iv' do
      expect(key_schedule.server_application_write_key)
        .to eq TESTBINARY_SERVER_APPLICATION_WRITE_KEY
      expect(key_schedule.server_application_write_iv)
        .to eq TESTBINARY_SERVER_APPLICATION_WRITE_IV
    end

    it 'should generete client application write_key, iv' do
      expect(key_schedule.client_application_write_key)
        .to eq TESTBINARY_CLIENT_APPLICATION_WRITE_KEY
      expect(key_schedule.client_application_write_iv)
        .to eq TESTBINARY_CLIENT_APPLICATION_WRITE_IV
    end
  end

  context 'key_schedule, Resumed 0-RTT Handshake,' do
    let(:key_schedule) do
      transcript = Transcript.new
      transcript.merge!(
        CH => ClientHello.deserialize(TESTBINARY_0_RTT_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_0_RTT_SERVER_HELLO),
        EE =>
        EncryptedExtensions.deserialize(TESTBINARY_0_RTT_ENCRYPTED_EXTENSIONS),
        SF => Finished.deserialize(TESTBINARY_0_RTT_SERVER_FINISHED),
        EOED => EndOfEarlyData.deserialize(TESTBINARY_0_RTT_END_OF_EARLY_DATA),
        CF => Finished.deserialize(TESTBINARY_0_RTT_CLIENT_FINISHED)
      )
      KeySchedule.new(psk: TESTBINARY_0_RTT_PSK,
                      shared_secret: TESTBINARY_0_RTT_SHARED_SECRET,
                      cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
                      transcript: transcript)
    end

    it 'should generate server parameters write_key, iv' do
      expect(key_schedule.server_handshake_write_key)
        .to eq TESTBINARY_0_RTT_SERVER_PARAMETERS_WRITE_KEY
      expect(key_schedule.server_handshake_write_iv)
        .to eq TESTBINARY_0_RTT_SERVER_PARAMETERS_WRITE_IV
    end

    it 'should generete client application write_key, iv' do
      expect(key_schedule.client_application_write_key)
        .to eq TESTBINARY_0_RTT_CLIENT_APPLICATION_WRITE_KEY
      expect(key_schedule.client_application_write_iv)
        .to eq TESTBINARY_0_RTT_CLIENT_APPLICATION_WRITE_IV
    end
  end

  context 'key_schedule, Resumed 0-RTT Handshake, ' \
          'not negotiated shared_secret yet,' do
    let(:key_schedule) do
      transcript = Transcript.new
      transcript[CH] = ClientHello.deserialize(TESTBINARY_0_RTT_CLIENT_HELLO)
      KeySchedule.new(psk: TESTBINARY_0_RTT_PSK,
                      shared_secret: nil,
                      cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
                      transcript: transcript)
    end

    it 'should generate binder key for resumption PSKs' do
      expect(key_schedule.binder_key_res)
        .to eq TESTBINARY_0_RTT_BINDER_KEY_RES
    end

    it 'should generate client_early_traffic_secret' do
      expect(key_schedule.client_early_traffic_secret)
        .to eq TESTBINARY_0_RTT_C_E_TRAFFIC
    end

    it 'should generate 0-RTT application write_key, iv' do
      expect(key_schedule.early_data_write_key)
        .to eq TESTBINARY_0_RTT_EARLY_DATA_WRITE_KEY
      expect(key_schedule.early_data_write_iv)
        .to eq TESTBINARY_0_RTT_EARLY_DATA_WRITE_IV
    end
  end

  context 'key_schedule, HelloRetryRequest,' do
    let(:key_schedule) do
      transcript = Transcript.new
      transcript.merge!(
        CH1 => ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO1),
        HRR => ServerHello.deserialize(TESTBINARY_HRR_HELLO_RETRY_REQUEST),
        CH => ClientHello.deserialize(TESTBINARY_HRR_CLIENT_HELLO),
        SH => ServerHello.deserialize(TESTBINARY_HRR_SERVER_HELLO),
        EE =>
        EncryptedExtensions.deserialize(TESTBINARY_HRR_ENCRYPTED_EXTENSIONS),
        CT => Certificate.deserialize(TESTBINARY_HRR_CERTIFICATE),
        CV => CertificateVerify.deserialize(TESTBINARY_HRR_CERTIFICATE_VERIFY),
        SF => Finished.deserialize(TESTBINARY_HRR_SERVER_FINISHED),
        CF => Finished.deserialize(TESTBINARY_HRR_CLIENT_FINISHED)
      )
      KeySchedule.new(shared_secret: TESTBINARY_HRR_SHARED_SECRET,
                      cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
                      transcript: transcript)
    end

    it 'should generate server finished_key' do
      expect(key_schedule.server_finished_key)
        .to eq TESTBINARY_HRR_SERVER_FINISHED_KEY
    end

    it 'should generate server parameters write_key, iv' do
      expect(key_schedule.server_handshake_write_key)
        .to eq TESTBINARY_HRR_SERVER_PARAMETERS_WRITE_KEY
      expect(key_schedule.server_handshake_write_iv)
        .to eq TESTBINARY_HRR_SERVER_PARAMETERS_WRITE_IV
    end

    it 'should generate client finished_key' do
      expect(key_schedule.client_finished_key)
        .to eq TESTBINARY_HRR_CLIENT_FINISHED_KEY
    end

    it 'should generate client finished write_key, iv' do
      expect(key_schedule.client_handshake_write_key)
        .to eq TESTBINARY_HRR_CLIENT_FINISHED_WRITE_KEY
      expect(key_schedule.client_handshake_write_iv)
        .to eq TESTBINARY_HRR_CLIENT_FINISHED_WRITE_IV
    end

    it 'should generete server application write_key, iv' do
      expect(key_schedule.server_application_write_key)
        .to eq TESTBINARY_HRR_SERVER_APPLICATION_WRITE_KEY
      expect(key_schedule.server_application_write_iv)
        .to eq TESTBINARY_HRR_SERVER_APPLICATION_WRITE_IV
    end

    it 'should generete client application write_key, iv' do
      expect(key_schedule.client_application_write_key)
        .to eq TESTBINARY_HRR_CLIENT_APPLICATION_WRITE_KEY
      expect(key_schedule.client_application_write_iv)
        .to eq TESTBINARY_HRR_CLIENT_APPLICATION_WRITE_IV
    end
  end
end
