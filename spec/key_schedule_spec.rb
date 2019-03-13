# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe KeySchedule do
  context 'key_schedule' do
    let(:key_schedule) do
      KeySchedule.new(digest: 'SHA256')
    end

    let(:ss) do
      TESTBINARY_SHARED_SECRET
    end

    let(:ch_sh) do
      TESTBINARY_CLIENT_HELLO \
      + TESTBINARY_SERVER_HELLO
    end

    let(:ch_sf) do
      ch_sh \
      + TESTBINARY_ENCRYPTED_EXTENSIONS \
      + TESTBINARY_CERTIFICATE \
      + TESTBINARY_CERTIFICATE_VERIFY \
      + TESTBINARY_SERVER_FINISHED
    end

    let(:ch_cf) do
      ch_sf \
      + TESTBINARY_CLIENT_FINISHED
    end

    it 'should generate secret' do
      expect(key_schedule.client_handshake_traffic_secret(ss, ch_sh))
        .to eq TESTBINARY_C_HS_TRAFFIC
      expect(key_schedule.server_handshake_traffic_secret(ss, ch_sh))
        .to eq TESTBINARY_S_HS_TRAFFIC
      expect(key_schedule.client_application_traffic_secret(ss, ch_sf))
        .to eq TESTBINARY_C_AP_TRAFFIC
      expect(key_schedule.server_application_traffic_secret(ss, ch_sf))
        .to eq TESTBINARY_S_AP_TRAFFIC
      expect(key_schedule.exporter_master_secret(ss, ch_sf))
        .to eq TESTBINARY_EXP_MASTER
      expect(key_schedule.resumption_master_secret(ss, ch_cf))
        .to eq TESTBINARY_RES_MASTER
    end
  end
end
