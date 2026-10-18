# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'

require_relative '../test_helper'

describe AuthProto::Encryption do
  describe "without ATPROTO_MASTER_KEY" do
    before do
      @original_master_key = ENV.delete("ATPROTO_MASTER_KEY")
    end

    after do
      ENV["ATPROTO_MASTER_KEY"] = @original_master_key
    end

    it "decrypts data using a separately created encryption service" do
      first = AuthProto::Encryption::Service.new
      encrypted = first.encrypt("access token", context: "data.access_token")
      second = AuthProto::Encryption::Service.new

      _(second.decrypt(encrypted, context: "data.access_token")).must_equal "access token"
    end

    it "generates the fallback key only once across key providers" do
      provider_class = Class.new(AuthProto::Encryption::KeyProvider)
      SecureRandom.expects(:random_bytes).with(32).once.returns("x" * 32)

      _stdout, stderr = capture_io do
        first = provider_class.new
        second = provider_class.new
        _(second.key_for_context("test")).must_equal first.key_for_context("test")
      end

      assert stderr.include?("Using randomly generated encryption key")
    end

    it "roundtrips a session with nested tokens through separate serializers" do
      session = AuthProto::State::Session.new(client_id: "test-client", scope: "atproto")
      session.tokens = AuthProto::State::TokenSet.new(
        access_token: "access", refresh_token: "refresh", token_type: "DPoP",
        expires_in: 3600, scope: "atproto", sub: "did:plc:alice"
      )

      serialized = AuthProto::Serialization::Session.new.serialize(session)
      restored = AuthProto::Serialization::Session.new.deserialize(serialized)

      _(restored.pkce_verifier).must_equal session.pkce_verifier
      _(restored.tokens.access_token).must_equal "access"
      _(restored.tokens.refresh_token).must_equal "refresh"
    end

    it "prefers an explicit environment key even after a fallback key was generated" do
      AuthProto::Encryption::KeyProvider.new
      ENV["ATPROTO_MASTER_KEY"] = Base64.strict_encode64("y" * 32)
      configured = AuthProto::Encryption::KeyProvider.new
      expected = AuthProto::Encryption::HKDF.derive(
        "y" * 32, salt: OpenSSL::Digest.digest("SHA256", "atproto-salt-test"), info: "atproto-test", length: 32
      )

      _(configured.key_for_context("test")).must_equal expected
    end
  end

  describe AuthProto::Encryption::Service do
    let(:encryption_service) { AuthProto::Encryption::Service.new }
    let(:sample_data) { "sensitive data" }
    let(:context) { "access_token" }

    describe "#encrypt" do
      it "encrypts data with a context" do
        result = encryption_service.encrypt(sample_data, context: context)

        assert_equal AuthProto::Encryption::Service::VERSION, result[:version]
        assert_kind_of String, result[:iv]
        assert_kind_of String, result[:data]
        assert_kind_of String, result[:tag]

        # Base64 validation
        assert Base64.strict_decode64(result[:iv])
        assert Base64.strict_decode64(result[:data])
        assert Base64.strict_decode64(result[:tag])
      end

      it "produces different ciphertexts for same data with different contexts" do
        result1 = encryption_service.encrypt(sample_data, context: "context1")
        result2 = encryption_service.encrypt(sample_data, context: "context2")

        refute_equal result1[:data], result2[:data]
      end

      it "produces different ciphertexts for same data and context due to IV" do
        result1 = encryption_service.encrypt(sample_data, context: context)
        result2 = encryption_service.encrypt(sample_data, context: context)

        refute_equal result1[:data], result2[:data]
        refute_equal result1[:iv], result2[:iv]
      end

      it "raises EncryptionError for nil data" do
        assert_raises(AuthProto::Encryption::EncryptionError, "Data cannot be nil") do
          encryption_service.encrypt(nil, context: context)
        end
      end

      it "raises EncryptionError for nil context" do
        assert_raises(AuthProto::Encryption::EncryptionError, "Context cannot be nil") do
          encryption_service.encrypt(sample_data, context: nil)
        end
      end

      it "raises EncryptionError for empty context" do
        assert_raises(AuthProto::Encryption::EncryptionError, "Context cannot be empty") do
          encryption_service.encrypt(sample_data, context: "")
        end
      end

      it "converts non-string data to string" do
        result = encryption_service.encrypt(123, context: context)
        decrypted = encryption_service.decrypt(result, context: context)
        assert_equal "123", decrypted
      end
    end

    describe "#decrypt" do
      it "correctly decrypts encrypted data" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        decrypted = encryption_service.decrypt(encrypted, context: context)

        assert_equal sample_data, decrypted
      end

      it "raises DecryptionError for wrong context" do
        encrypted = encryption_service.encrypt(sample_data, context: context)

        assert_raises(AuthProto::Encryption::DecryptionError) do
          encryption_service.decrypt(encrypted, context: "wrong_context")
        end
      end

      it "raises DecryptionError for tampered data" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:data] = Base64.strict_encode64("tampered")

        assert_raises(AuthProto::Encryption::DecryptionError) do
          encryption_service.decrypt(encrypted, context: context)
        end
      end

      it "raises DecryptionError for tampered auth tag" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:tag] = Base64.strict_encode64("tampered")

        assert_raises(AuthProto::Encryption::DecryptionError) do
          encryption_service.decrypt(encrypted, context: context)
        end
      end

      it "raises DecryptionError for nil encrypted data" do
        assert_raises(AuthProto::Encryption::DecryptionError, "Encrypted data cannot be nil") do
          encryption_service.decrypt(nil, context: context)
        end
      end

      it "raises DecryptionError for nil context" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        assert_raises(AuthProto::Encryption::DecryptionError, "Context cannot be nil") do
          encryption_service.decrypt(encrypted, context: nil)
        end
      end

      it "raises DecryptionError for invalid format" do
        assert_raises(AuthProto::Encryption::DecryptionError) do
          encryption_service.decrypt({ invalid: "format" }, context: context)
        end
      end

      it "raises DecryptionError for wrong version" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:version] = 999

        assert_raises(AuthProto::Encryption::DecryptionError) do
          encryption_service.decrypt(encrypted, context: context)
        end
      end
    end
  end

  describe AuthProto::Encryption::KeyProvider do
    let(:key_provider) { AuthProto::Encryption::KeyProvider.new }

    describe "#key_for_context" do
      it "derives different keys for different contexts" do
        key1 = key_provider.key_for_context("context1")
        key2 = key_provider.key_for_context("context2")

        refute_equal key1, key2
      end

      it "derives consistent keys for same context" do
        key1 = key_provider.key_for_context("context")
        key2 = key_provider.key_for_context("context")

        assert_equal key1, key2
      end

      it "returns keys of correct length for AES-256" do
        key = key_provider.key_for_context("context")
        assert_equal 32, key.bytesize
      end

      it "raises ConfigurationError for nil context" do
        assert_raises(AuthProto::Encryption::ConfigurationError) do
          key_provider.key_for_context(nil)
        end
      end
    end
  end
end
