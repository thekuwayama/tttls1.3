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
    def build(group, key_exchange)
      case group
      when NamedGroup::SECP256R1, NamedGroup::SECP384R1, NamedGroup::SECP521R1
        curve = NamedGroup.curve_name(group)
        pub_key = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new(curve),
          OpenSSL::BN.new(key_exchange, 2)
        )
        @priv_keys[group].dh_compute_key(pub_key)
      else
        # not supported other NamedGroup
        raise Error::ErrorAlerts, :internal_error
      end
    end

    # @return [Array of TTTLS13::Message::Extensions::KeyShare]
    def key_share_entries
      @priv_keys.map do |group, priv_key|
        case group
        when NamedGroup::SECP256R1, NamedGroup::SECP384R1, NamedGroup::SECP521R1
          Message::Extension::KeyShareEntry.new(
            group: group,
            key_exchange: priv_key.public_key.to_octet_string(:uncompressed)
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
        else
          # not supported other NamedGroup
          raise Error::ErrorAlerts, :internal_error
        end
      end

      shared_secret
    end
  end
end
