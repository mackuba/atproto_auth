# frozen_string_literal: true

require 'uri'

describe AuthProto::ServerMetadata::OriginUrl do
  let(:valid_url) { "https://example.com" }
  let(:valid_url_with_port) { "https://example.com:8443" }
  let(:url_with_http) { "http://example.com" }
  let(:url_with_path) { "https://example.com/path" }
  let(:url_with_query) { "https://example.com?query=1" }
  let(:url_with_fragment) { "https://example.com#fragment" }
  let(:url_with_userinfo) { "https://user:pass@example.com" }
  let(:url_with_default_port) { "https://example.com:443" }
  let(:malformed_url) { "not a url" }

  describe "#valid?" do
    it "should return true for a valid origin URL" do
      origin_url = AuthProto::ServerMetadata::OriginUrl.new(valid_url)
      origin_url.valid?.should be true
    end

    it "should return true for a valid origin URL with a non-default port" do
      origin_url = AuthProto::ServerMetadata::OriginUrl.new(valid_url_with_port)
      origin_url.valid?.should be true
    end

    it "should return false for a URL using HTTP scheme" do
      origin_url = AuthProto::ServerMetadata::OriginUrl.new(url_with_http)
      origin_url.valid?.should be false
    end

    it "should return false for a URL with a non-root path" do
      origin_url = AuthProto::ServerMetadata::OriginUrl.new(url_with_path)
      origin_url.valid?.should be false
    end

    it "should return false for a URL with a query string" do
      origin_url = AuthProto::ServerMetadata::OriginUrl.new(url_with_query)
      origin_url.valid?.should be false
    end

    it "should return false for a URL with a fragment" do
      origin_url = AuthProto::ServerMetadata::OriginUrl.new(url_with_fragment)
      origin_url.valid?.should be false
    end

    it "should return false for a URL with userinfo (credentials)" do
      origin_url = AuthProto::ServerMetadata::OriginUrl.new(url_with_userinfo)
      origin_url.valid?.should be false
    end

    it "should return false for a URL with the default HTTPS port (443)" do
      origin_url = AuthProto::ServerMetadata::OriginUrl.new(url_with_default_port)
      origin_url.valid?.should be false
    end

    it "should raise an error for a malformed URL" do
      expect {
        AuthProto::ServerMetadata::OriginUrl.new(malformed_url).valid?
      }.to raise_error(URI::InvalidURIError)
    end
  end
end
