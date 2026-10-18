# frozen_string_literal: true

require 'json'

describe AuthProto::ServerMetadata::ResourceServer do
  let(:valid_metadata) { { "authorization_servers" => ["https://auth.example.com"] } }
  let(:invalid_metadata_missing_servers) { {} }
  let(:invalid_metadata_multiple_servers) { { "authorization_servers" => ["https://auth1.example.com", "https://auth2.example.com"] } }
  let(:invalid_metadata_bad_url) { { "authorization_servers" => ["http://auth.example.com"] } }
  let(:valid_url) { "https://example.com" }
  let(:mock_response) { { body: valid_metadata.to_json } }

  describe "#initialize" do
    it "should initialize successfully with valid metadata" do
      server = AuthProto::ServerMetadata::ResourceServer.new(valid_metadata)
      server.authorization_servers.should == valid_metadata["authorization_servers"]
    end

    it "should raise an error if authorization_servers is missing" do
      expect {
        AuthProto::ServerMetadata::ResourceServer.new(invalid_metadata_missing_servers)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error if there are multiple authorization_servers" do
      expect {
        AuthProto::ServerMetadata::ResourceServer.new(invalid_metadata_multiple_servers)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error for invalid authorization server URL format" do
      expect {
        AuthProto::ServerMetadata::ResourceServer.new(invalid_metadata_bad_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end
  end

  describe ".from_url" do
    before do
      AuthProto.configuration.stubs(:http_client).returns(mock_http_client = mock)
      mock_http_client.stubs(:get).with("#{valid_url}/.well-known/oauth-protected-resource").returns(mock_response)
    end

    it "should fetch and parse metadata successfully" do
      server = AuthProto::ServerMetadata::ResourceServer.from_url(valid_url)
      server.authorization_servers.should == valid_metadata["authorization_servers"]
    end

    it "should raise an error if fetching metadata fails" do
      AuthProto.configuration.http_client.stubs(:get).raises(AuthProto::HTTPClient::HTTPError.new("Network error",
                                                                                                      {}))
      expect {
        AuthProto::ServerMetadata::ResourceServer.from_url(valid_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error if the metadata JSON is invalid" do
      AuthProto.configuration.http_client.stubs(:get).returns(body: "not-json")
      expect {
        AuthProto::ServerMetadata::ResourceServer.from_url(valid_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end
  end
end
