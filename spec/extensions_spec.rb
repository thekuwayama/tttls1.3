# encoding: ascii-8bit
# frozen_string_literal: true

require_relative 'spec_helper'
using Refinements

RSpec.describe Extensions do
  context 'empty extensions' do
    let(:extensions) do
      Extensions.new
    end

    it 'should be generated' do
      expect(extensions).to be_empty
    end

    it 'should be serialized' do
      expect(extensions.serialize).to eq "\x00\x00"
    end
  end

  let(:supported_versions) do
    SupportedVersions.new(
      msg_type: HandshakeType::CLIENT_HELLO,
      versions: [ProtocolVersion::TLS_1_3]
    )
  end

  let(:signature_algorithms) do
    SignatureAlgorithms.new([SignatureScheme::RSA_PSS_RSAE_SHA256])
  end

  let(:supported_groups) do
    SupportedGroups.new([NamedGroup::SECP256R1])
  end

  let(:key_share) do
    ec = OpenSSL::PKey::EC.generate('prime256v1')
    KeyShare.new(
      msg_type: HandshakeType::CLIENT_HELLO,
      key_share_entry: [
        KeyShareEntry.new(
          group: NamedGroup::SECP256R1,
          key_exchange: ec.public_key.to_octet_string(:uncompressed)
        )
      ]
    )
  end

  let(:server_name) do
    ServerName.new('example.com')
  end

  let(:base_exs) do
    [
      supported_versions,
      signature_algorithms,
      supported_groups,
      key_share,
      server_name
    ]
  end

  context 'client_hello base extensions' do
    let(:extensions) do
      Extensions.new(base_exs)
    end

    it 'should be generated' do
      expect(extensions)
        .to include ExtensionType::SUPPORTED_VERSIONS => supported_versions
      expect(extensions)
        .to include ExtensionType::SIGNATURE_ALGORITHMS => signature_algorithms
      expect(extensions)
        .to include ExtensionType::SUPPORTED_GROUPS => supported_groups
      expect(extensions)
        .to include ExtensionType::KEY_SHARE => key_share
      expect(extensions)
        .to include ExtensionType::SERVER_NAME => server_name
    end
  end

  context 'extensions that include pre_shared_key' do
    let(:pre_shared_key) do
      PreSharedKey.deserialize(TESTBINARY_PRE_SHARED_KEY_CH,
                               HandshakeType::CLIENT_HELLO)
    end

    let(:extensions) do
      exs = [pre_shared_key] + base_exs
      Extensions.new(exs)
    end

    it 'should be generated' do
      expect(extensions)
        .to include ExtensionType::SUPPORTED_VERSIONS => supported_versions
      expect(extensions)
        .to include ExtensionType::SIGNATURE_ALGORITHMS => signature_algorithms
      expect(extensions)
        .to include ExtensionType::SUPPORTED_GROUPS => supported_groups
      expect(extensions)
        .to include ExtensionType::KEY_SHARE => key_share
      expect(extensions)
        .to include ExtensionType::SERVER_NAME => server_name
      expect(extensions)
        .to include ExtensionType::PRE_SHARED_KEY => pre_shared_key
    end

    it 'should be serialized end with pre_shared_key' do
      expect(extensions.serialize).to end_with TESTBINARY_PRE_SHARED_KEY_CH
    end
  end

  context 'extensions that include GREASE' do
    let(:unknown_exs_key_aa) do
      "\xaa\xaa"
    end

    let(:unknown_exs_key_bb) do
      "\xbb\xbb"
    end

    let(:grease_aa) do
      UnknownExtension.new(extension_type: unknown_exs_key_aa,
                           extension_data: '')
    end

    let(:grease_bb) do
      UnknownExtension.new(extension_type: unknown_exs_key_bb,
                           extension_data: "\x00")
    end

    let(:extensions) do
      exs = [grease_aa] + base_exs + [grease_bb]
      Extensions.new(exs)
    end

    it 'should be generated' do
      expect(extensions)
        .to include ExtensionType::SUPPORTED_VERSIONS => supported_versions
      expect(extensions)
        .to include ExtensionType::SIGNATURE_ALGORITHMS => signature_algorithms
      expect(extensions)
        .to include ExtensionType::SUPPORTED_GROUPS => supported_groups
      expect(extensions)
        .to include ExtensionType::KEY_SHARE => key_share
      expect(extensions)
        .to include ExtensionType::SERVER_NAME => server_name
      # ignore UnknownExtension, so return nil
      expect(extensions).to include unknown_exs_key_aa => nil
      expect(extensions).to include unknown_exs_key_bb => nil
    end
  end

  context 'extensions binary' do
    let(:extensions) do
      Extensions.deserialize(TESTBINARY_EXTENSIONS,
                             HandshakeType::CLIENT_HELLO)
    end

    it 'should generate object' do
      expect(extensions).to include ExtensionType::SUPPORTED_GROUPS
      expect(extensions).to include ExtensionType::KEY_SHARE
      expect(extensions).to include ExtensionType::SUPPORTED_VERSIONS
      expect(extensions).to include ExtensionType::SIGNATURE_ALGORITHMS
      expect(extensions).to include ExtensionType::PSK_KEY_EXCHANGE_MODES
      expect(extensions).to include ExtensionType::RECORD_SIZE_LIMIT
    end
  end

  context 'duplicated extension_type' do
    let(:server_name) do
      ServerName.new('example.com')
    end

    let(:testbinary) do
      server_name.serialize * 2
    end

    it 'should raise error, if extension_type get duplicated' do
      expect { Extensions.deserialize(testbinary, HandshakeType::CLIENT_HELLO) }
        .to raise_error(ErrorAlerts)
    end
  end

  context 'removing and replacing extensions from EncodedClientHelloInner' do
    let(:extensions) do
      extensions, = Client.new(nil, 'localhost').send(:gen_ch_extensions)
      extensions
    end

    let(:no_key_share_exs) do
      Extensions.new(
        extensions.filter { |k, _| k != ExtensionType::KEY_SHARE }.values
      )
    end

    it 'should be equal remove_and_replace! with []' do
      expected = extensions.clone
      got = extensions.remove_and_replace!([])

      expect(got.keys).to eq expected.keys
      expect(got[ExtensionType::ECH_OUTER_EXTENSIONS]).to eq nil
      expect(extensions.keys - got.keys).to eq []
    end

    it 'should be equal remove_and_replace! with [key_share]' do
      expected = extensions.filter { |k, _| k != ExtensionType::KEY_SHARE }
      expected[ExtensionType::ECH_OUTER_EXTENSIONS] = \
        Extension::ECHOuterExtensions.new([ExtensionType::KEY_SHARE])
      got = extensions.remove_and_replace!([ExtensionType::KEY_SHARE])

      expect(got.keys).to eq expected.keys
      expect(got[ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions)
        .to eq expected[ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions
      expect(extensions.keys - got.keys)
        .to eq expected[ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions
    end

    it 'should be equal remove_and_replace! with' \
       ' [key_share,supported_versions]' do
      outer_extensions = [
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_VERSIONS
      ]
      expected = extensions.filter { |k, _| !outer_extensions.include?(k) }
      expected[ExtensionType::ECH_OUTER_EXTENSIONS] = \
        Extension::ECHOuterExtensions.new(
          extensions.filter { |k, _| outer_extensions.include?(k) }.keys
        )
      got = extensions.remove_and_replace!(outer_extensions)

      expect(got.keys).to eq expected.keys
      expect(got[ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions)
        .to eq expected[ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions
      expect(extensions.keys - got.keys)
        .to eq expected[ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions
    end

    it 'should be equal remove_and_replace! with no key_share extensions' \
       ' & [key_share]' do
      expected = no_key_share_exs.clone
      got = no_key_share_exs.remove_and_replace!([ExtensionType::KEY_SHARE])

      expect(got).to eq expected
      expect(got[ExtensionType::ECH_OUTER_EXTENSIONS]).to eq nil
      expect(no_key_share_exs.keys - got.keys).to eq []
    end
  end
end
