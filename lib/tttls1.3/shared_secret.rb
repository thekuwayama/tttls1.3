# encoding: ascii-8bit
# frozen_string_literal: true

module TTTLS13
  class SharedSecret
    def initialize
      @priv_keys = {}
    end

    # @param group [TTTLS13::NamedGroup]
    # @param priv_key [OpenSSL::PKey::EC.$Object | OpenSSL::PKey::PKey.$Object]
    def store!(group, priv_key)
      @priv_keys[group] = priv_key
    end

    # @param group [TTTLS13::NamedGroup]
    # @param key_exchange [String]
    #
    # @return String
    # rubocop: disable Metrics/MethodLength
    def build(group, key_exchange)
      case group
      when NamedGroup::SECP256R1, NamedGroup::SECP384R1, NamedGroup::SECP521R1
        curve = NamedGroup.curve_name(group)
        pub_key = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new(curve),
          OpenSSL::BN.new(key_exchange, 2)
        )
        @priv_keys[group].dh_compute_key(pub_key)
      when NamedGroup::X25519
        asn1_seq = OpenSSL::ASN1.Sequence(
          [
            OpenSSL::ASN1.Sequence(
              [
                # https://datatracker.ietf.org/doc/html/rfc8410#section-3
                OpenSSL::ASN1.ObjectId('1.3.101.110')
              ]
            ),
            OpenSSL::ASN1.BitString(key_exchange)
          ]
        )

        @priv_keys[group].derive(OpenSSL::PKey.read(asn1_seq.to_der))
      when NamedGroup::X448
        asn1_seq = OpenSSL::ASN1.Sequence(
          [
            OpenSSL::ASN1.Sequence(
              [
                # https://datatracker.ietf.org/doc/html/rfc8410#section-3
                OpenSSL::ASN1.ObjectId('1.3.101.111')
              ]
            ),
            OpenSSL::ASN1.BitString(key_exchange)
          ]
        )

        @priv_keys[group].derive(OpenSSL::PKey.read(asn1_seq.to_der))
      else
        # not supported other NamedGroup
        raise Error::ErrorAlerts, :internal_error
      end
    end
    # rubocop: enable Metrics/MethodLength

    # @return [Array of TTTLS13::Message::Extensions::KeyShare]
    def key_share_entries
      @priv_keys.map do |group, priv_key|
        case group
        when NamedGroup::SECP256R1, NamedGroup::SECP384R1, NamedGroup::SECP521R1
          Message::Extension::KeyShareEntry.new(
            group: group,
            key_exchange: priv_key.public_key.to_octet_string(:uncompressed)
          )
        when NamedGroup::X25519, NamedGroup::X448
          n_pk = NamedGroup.key_exchange_len(group)
          Message::Extension::KeyShareEntry.new(
            group: group,
            key_exchange: priv_key.public_to_der[-n_pk, n_pk]
          )
        else
          # not supported other NamedGroup
          raise Error::ErrorAlerts, :internal_error
        end
      end
    end

    # @param group [TTTLS13::Message::Extension::NamedGroup]
    #
    # @return [OpenSSL::PKey::EC.$Object | OpenSSL::PKey::PKey.$Object]]
    def [](group)
      @priv_keys[group]
    end

    # @param groups [Array of TTTLS13::NamedGroup]
    #
    # @return [TTTLS13::SharedSecret]
    def self.gen_from_named_groups(groups)
      shared_secret = SharedSecret.new

      groups.each do |group|
        case group
        when NamedGroup::SECP256R1, NamedGroup::SECP384R1, NamedGroup::SECP521R1
          curve = NamedGroup.curve_name(group)
          ec = OpenSSL::PKey::EC.generate(curve)
          shared_secret.store!(group, ec)
        when NamedGroup::X25519, NamedGroup::X448
          pkey = OpenSSL::PKey.generate_key(NamedGroup.curve_name(group))
          shared_secret.store!(group, pkey)
        else
          # not supported other NamedGroup
          raise Error::ErrorAlerts, :internal_error
        end
      end

      shared_secret
    end
  end
end
