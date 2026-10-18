# frozen_string_literal: true

require 'json'

describe AuthProto::ClientMetadata do
  before do
    @valid_metadata = {
      "client_id" => "https://example.com/metadata.json",
      "grant_types" => %w[authorization_code refresh_token],
      "response_types" => ["code"],
      "redirect_uris" => ["https://example.com/callback"],
      "scope" => "atproto offline_access",
      "dpop_bound_access_tokens" => true,
      "client_name" => "Example Client",
      "application_type" => "web"
    }
  end

  describe "initialization" do
    it "should initialize with valid metadata" do
      client_metadata = AuthProto::ClientMetadata.new(@valid_metadata)
      client_metadata.client_id.should == "https://example.com/metadata.json"
      client_metadata.grant_types.should == %w[authorization_code refresh_token]
      client_metadata.response_types.should == ["code"]
      client_metadata.redirect_uris.should == ["https://example.com/callback"]
      client_metadata.scope.should == "atproto offline_access"
      client_metadata.client_name.should == "Example Client"
      client_metadata.application_type.should == "web"
    end

    it "should initialize with localhost client_id" do
      @valid_metadata["client_id"] = "http://localhost"
      @valid_metadata["redirect_uris"] = ["http://127.0.0.1:9292/callback"]
      client_metadata = AuthProto::ClientMetadata.new(@valid_metadata)
      client_metadata.client_id.should == "http://localhost"
    end

    it "should raise an error when client_id is missing" do
      @valid_metadata.delete("client_id")
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for invalid client_id scheme" do
      @valid_metadata["client_id"] = "http://example.com"
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for invalid grant types" do
      @valid_metadata["grant_types"] = ["invalid_grant"]
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error when redirect URIs are missing" do
      @valid_metadata.delete("redirect_uris")
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for invalid redirect URI scheme" do
      @valid_metadata["redirect_uris"] = ["http://example.com/callback"]
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for invalid scope" do
      @valid_metadata["scope"] = "invalid_scope"
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for missing dpop_bound_access_tokens" do
      @valid_metadata.delete("dpop_bound_access_tokens")
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end
  end

  describe ".from_url" do
    it "should create an instance from valid URL metadata" do
      AuthProto::ClientMetadata.stubs(:fetch_metadata).returns({ body: @valid_metadata.to_json })
      client_metadata = AuthProto::ClientMetadata.from_url("https://example.com/metadata.json")
      client_metadata.should be_an_instance_of(AuthProto::ClientMetadata)
      client_metadata.client_id.should == "https://example.com/metadata.json"
    end

    it "should raise an error for invalid URL scheme" do
      expect {
        AuthProto::ClientMetadata.from_url("http://example.com/metadata")
      }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for client_id mismatch in metadata" do
      AuthProto::ClientMetadata.stubs(:fetch_metadata).returns({ body: @valid_metadata.to_json })
      @valid_metadata["client_id"] = "https://otherexample.com"
      expect {
        AuthProto::ClientMetadata.from_url("https://example.com/metadata")
      }.to raise_error(AuthProto::InvalidClientMetadata)
    end
  end

  describe "#confidential?" do
    it "should return true for confidential clients using private_key_jwt" do
      @valid_metadata["token_endpoint_auth_method"] = "private_key_jwt"
      @valid_metadata["token_endpoint_auth_signing_alg"] = "ES256"
      @valid_metadata["jwks"] = { "keys" => [] }
      client_metadata = AuthProto::ClientMetadata.new(@valid_metadata)
      client_metadata.confidential?.should be true
    end

    it "should return false for non-confidential clients" do
      client_metadata = AuthProto::ClientMetadata.new(@valid_metadata)
      client_metadata.confidential?.should be false
    end
  end
end
