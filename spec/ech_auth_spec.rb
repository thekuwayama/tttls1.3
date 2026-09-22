# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe ECH::Auth do
  let(:key) do
    OpenSSL::PKey::EC.generate('prime256v1')
  end

  let(:spki) do
    key.public_to_der
  end

  let(:algorithm) do
    ECDSA_SECP256R1_SHA256.unpack1('n')
  end

  let(:digest) do
    'SHA256'
  end

  let(:not_after) do
    Time.now.to_i + 3600
  end

  let(:trusted_keys) do
    [OpenSSL::Digest.digest('SHA256', spki)]
  end

  let(:key_config) do
    hkc = ECHConfig::ECHConfigContents::HpkeKeyConfig
    hkc.new(
      0,
      hkc::HpkeKemId.new(0x0020),
      hkc::HpkePublicKey.new("\x00" * 32),
      [
        hkc::HpkeSymmetricCipherSuite.new(
          hkc::HpkeSymmetricCipherSuite::HpkeKdfId.new(0x0001),
          hkc::HpkeSymmetricCipherSuite::HpkeAeadId.new(0x0001)
        )
      ]
    )
  end

  let(:retry_config) do
    unsigned = ECH::Auth::ECHAuth.new(not_after, 0, spki, algorithm, '')
    signature = key.sign(digest, echconfig(unsigned).to_be_signed)
    echconfig(ECH::Auth::ECHAuth.new(not_after, 0, spki, algorithm, signature))
  end

  let(:unauthentic) do
    signature = key.sign(digest, 'not the to_be_signed')
    echconfig(ECH::Auth::ECHAuth.new(not_after, 0, spki, algorithm, signature))
  end

  # an extension type whose high order bit is set is mandatory
  let(:unsupported_mandatory) do
    ECHConfig::ECHConfigContents::Extensions::UnknownExtension.new(0x8001)
  end

  # the extensions are the only part these examples vary
  def echconfig(*extensions)
    ECHConfig.new(
      "\xfe\x0d",
      ECHConfig::ECHConfigContents.new(
        key_config,
        0,
        'localhost',
        ECHConfig::ECHConfigContents::Extensions.new(extensions.compact)
      )
    )
  end

  context 'retry_config, whose ech_auth is signed by a trusted key' do
    it 'should be authenticated' do
      expect(ECH::Auth.authenticated?(retry_config, trusted_keys, Time.now))
        .to be true
    end

    it 'should NOT be authenticated, if not_after has passed' do
      # not_after is strictly greater than the current time
      now = Time.at(not_after)
      expect(ECH::Auth.authenticated?(retry_config, trusted_keys, now))
        .to be false
      expect(ECH::Auth.authenticated?(retry_config, trusted_keys, now + 1))
        .to be false
    end
  end

  context 'retry_config, whose spki is NOT in trusted_keys' do
    let(:trusted_keys) do
      [OpenSSL::Digest.digest('SHA256', "\x00" * 32)]
    end

    it 'should NOT be authenticated' do
      expect(ECH::Auth.authenticated?(retry_config, trusted_keys, Time.now))
        .to be false
    end
  end

  context 'retry_config, whose signature covers other bytes' do
    it 'should NOT be authenticated' do
      expect(ECH::Auth.authenticated?(unauthentic, trusted_keys, Time.now))
        .to be false
    end
  end

  context 'retry_config, whose ech_auth is signed with an ED25519 key' do
    let(:key) do
      OpenSSL::PKey.generate_key('ED25519')
    end

    let(:algorithm) do
      ED25519.unpack1('n')
    end

    let(:digest) do
      nil
    end

    it 'should be authenticated' do
      expect(ECH::Auth.authenticated?(retry_config, trusted_keys, Time.now))
        .to be true
    end

    it 'should NOT be authenticated, whose signature covers other bytes' do
      expect(ECH::Auth.authenticated?(unauthentic, trusted_keys, Time.now))
        .to be false
    end
  end

  context 'retry_config, whose algorithm is unsupported' do
    # ED448
    let(:algorithm) do
      0x0808
    end

    it 'should NOT be authenticated' do
      expect(ECH::Auth.authenticated?(retry_config, trusted_keys, Time.now))
        .to be false
    end
  end

  context 'retry_config, which has NO ech_auth' do
    it 'should NOT be authenticated' do
      expect(ECH::Auth.authenticated?(echconfig(nil), trusted_keys, Time.now))
        .to be false
    end
  end

  context 'retry_configs' do
    it 'should be filtered by authentication' do
      expect(
        ECH::Auth.authenticate([unauthentic, retry_config, echconfig(nil)],
                               trusted_keys,
                               Time.now)
      ).to eq [retry_config]
    end
  end

  context 'ECHConfig, which has ech_authinfo' do
    it 'should record trusted_keys' do
      ech_config = echconfig(ECH::Auth::ECHAuthInfo.new(trusted_keys))
      expect(ECH::Auth.trusted_keys(ech_config)).to eq trusted_keys
      expect(ECH::Auth.trusted_keys(echconfig(nil))).to be_nil
      expect(ECH::Auth.trusted_keys(nil)).to be_nil
    end

    it 'should NOT record trusted_keys, if it is ignored' do
      ech_config = echconfig(ECH::Auth::ECHAuthInfo.new(trusted_keys),
                             unsupported_mandatory)
      expect(ECH::Auth.trusted_keys(ech_config)).to be_nil
    end
  end

  context 'client, whose ech_config has ech_authinfo' do
    let(:client) do
      Client.new(
        nil,
        'localhost',
        ech_config: echconfig(ECH::Auth::ECHAuthInfo.new(trusted_keys)),
        ech_hpke_cipher_suites:
          STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES
      )
    end

    it 'should return only authenticated retry_configs' do
      client.instance_variable_set(:@retry_configs,
                                   [unauthentic, retry_config])
      expect(client.retry_configs).to eq [retry_config]
    end
  end

  context 'client, whose ech_config has NO ech_authinfo' do
    let(:client) do
      Client.new(
        nil,
        'localhost',
        ech_config: echconfig(nil),
        ech_hpke_cipher_suites:
          STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES
      )
    end

    it 'should NOT authenticate retry_configs' do
      client.instance_variable_set(:@retry_configs, [unauthentic])
      expect(client.retry_configs).to eq [unauthentic]
    end

    it 'should return empty, before EncryptedExtensions is received' do
      expect(client.retry_configs).to eq []
    end

    it 'should NOT return retry_configs, which have to be ignored' do
      client.instance_variable_set(:@retry_configs,
                                   [echconfig(unsupported_mandatory)])
      expect(client.retry_configs).to eq []
    end
  end
end
