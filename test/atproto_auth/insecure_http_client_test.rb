# frozen_string_literal: true

require_relative '../test_helper'

describe AuthProto::InsecureHttpClient do
  let(:client) { AuthProto::InsecureHttpClient.new }

  it "supports GET and POST over HTTP and HTTPS at public and local destinations" do
    urls = %w[
      http://localhost:9292/test http://127.0.0.1:9292/test http://[::1]:9292/test
      http://192.168.1.1/test http://dev.example.com/test https://plc.directory/test https://127.0.0.1:9292/test
    ]
    urls.each do |url|
      stub_request(:get, url).with(headers: { "Cache-Control" => "no-store" })
                             .to_return(status: 200, body: "ok")
      stub_request(:post, url).with(body: "test=value", headers: { "X-Test" => "yes" })
                              .to_return(status: 201, body: "created")

      _(client.get(url)[:body]).must_equal "ok"
      _(client.post(url, body: { test: "value" }, headers: { "X-Test" => "yes" })[:status]).must_equal 201
    end
  end

  it "uses the same shared client for remote identity discovery and local requests" do
    previous_configuration = AuthProto.configuration
    AuthProto.reset_configuration!
    AuthProto.configure { |config| config.http_client = client }
    Resolv::DNS.any_instance.stubs(:getresources).returns([])
    stub_request(:get, "https://alice.example.com/.well-known/atproto-did")
      .to_return(status: 200, body: "did:plc:alice")
    stub_request(:get, "https://plc.directory/did:plc:alice").to_return(status: 200, body: {
      id: "did:plc:alice", pds: "https://pds.example.com"
    }.to_json)
    stub_request(:post, "http://localhost:9292/token").to_return(status: 200, body: "local")

    result = AuthProto::Identity::Resolver.new.resolve_handle("alice.example.com")
    _(result[:did]).must_equal "did:plc:alice"
    _(AuthProto.configuration.http_client.post("http://localhost:9292/token")[:body]).must_equal "local"
  ensure
    AuthProto.configuration = previous_configuration
  end

  it "follows GET and POST redirects between HTTPS and local HTTP" do
    remote = "https://example.com/start"
    local = "http://localhost:9292/next"
    final = "https://example.com/final"
    %i[get post].each do |method|
      stub_request(method, remote).to_return(status: 307, headers: { "Location" => local })
      stub_request(method, local).to_return(status: 307, headers: { "Location" => final })
      stub_request(method, final).to_return(status: 200, body: "ok")
      _(client.public_send(method, remote)[:body]).must_equal "ok"
    end
  end

  it "still rejects unsupported schemes, missing hosts and fragments" do
    %w[ftp://localhost/test file:///tmp/test https:///test http://localhost/test#fragment].each do |url|
      _(-> { client.get(url) }).must_raise AuthProto::HttpClient::SSRFError
    end
  end

  it "keeps HTTPS certificate verification enabled and honors timeouts" do
    http = Net::HTTP.new("example.com")
    configured = AuthProto::InsecureHttpClient.new(timeout: 3)
    configured.send(:configure_http_client!, http)
    _(http.use_ssl?).must_equal true
    _(http.verify_mode).must_equal OpenSSL::SSL::VERIFY_PEER
    _(http.open_timeout).must_equal 3
    _(http.read_timeout).must_equal 3
  end

  it "retains response size limits" do
    url = "http://localhost:9292/test"
    stub_request(:get, url).to_return(status: 200, headers: {
                                        "Content-Length" => (AuthProto::HttpClient::MAX_RESPONSE_SIZE + 1).to_s
                                      })
    _(-> { client.get(url) }).must_raise AuthProto::HttpClient::HttpError
  end
end
