# frozen_string_literal: true

require_relative '../test_helper'

describe AuthProto::HttpClient do
  let(:client) { AuthProto::HttpClient.new }
  let(:sample_url) { "https://example.com/resource" }
  let(:private_ip) { "192.168.1.1" }

  before do
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
  end

  describe "request validation" do
    it "rejects non-HTTPS URLs" do
      assert_raises(AuthProto::HttpClient::SSRFError) do
        client.get("http://example.com")
      end
    end

    it "rejects URLs with fragments" do
      assert_raises(AuthProto::HttpClient::SSRFError) do
        client.get("https://example.com#fragment")
      end
    end

    it "rejects URLs without hosts" do
      assert_raises(AuthProto::HttpClient::SSRFError) do
        client.get("https:///resource")
      end
    end

    it "rejects private network IPs" do
      stub_request(:get, "https://#{private_ip}/")
        .to_return(status: 200, body: "")

      assert_raises(AuthProto::HttpClient::SSRFError) do
        client.get("https://#{private_ip}/")
      end
    end

    it "rejects loopback and IPv4-mapped IPv6 addresses" do
      %w[127.0.0.1 127.10.20.30 [::1] [::ffff:127.0.0.1]].each do |host|
        assert_raises(AuthProto::HttpClient::SSRFError) { client.get("https://#{host}/") }
      end
    end

    it "rejects hostnames resolving to any forbidden address" do
      Resolv::DNS.any_instance.stubs(:getaddresses).returns([
                                                              Resolv::IPv4.create("93.184.216.34"), Resolv::IPv6.create("::1")
                                                            ])
      assert_raises(AuthProto::HttpClient::SSRFError) { client.get(sample_url) }
    end

    it "rejects hostnames without resolved addresses" do
      Resolv::DNS.any_instance.stubs(:getaddresses).returns([])
      assert_raises(AuthProto::HttpClient::SSRFError) { client.get(sample_url) }
    end
  end

  describe "#get" do
    before do
      stub_request(:get, sample_url)
        .to_return(status: 200, body: "success", headers: { "Content-Type" => "text/plain" })
    end

    it "makes successful GET requests" do
      response = client.get(sample_url)
      assert_equal 200, response[:status]
      assert_equal "success", response[:body]
    end

    it "includes security headers" do
      stub_request(:get, sample_url)
        .with(headers: { "Cache-Control" => "no-store" })
        .to_return(status: 200, body: "")

      client.get(sample_url)
      assert_requested :get, sample_url, headers: { "Cache-Control" => "no-store" }
    end

    it "forwards user headers" do
      custom_headers = { "X-Custom" => "value" }

      stub_request(:get, sample_url)
        .with(headers: custom_headers)
        .to_return(status: 200, body: "")

      client.get(sample_url, custom_headers)
      assert_requested :get, sample_url, headers: custom_headers
    end

    it "follows redirects up to limit" do
      redirect_url = "https://example.com/final"

      stub_request(:get, sample_url)
        .to_return(status: 302, headers: { "Location" => redirect_url })
      stub_request(:get, redirect_url)
        .to_return(status: 200, body: "redirected")

      response = client.get(sample_url)
      assert_equal "redirected", response[:body]
    end

    it "prevents redirect loops" do
      stub_request(:get, sample_url)
        .to_return(status: 302, headers: { "Location" => sample_url })

      assert_raises(AuthProto::HttpClient::HttpError) do
        client.get(sample_url)
      end
    end

    it "rejects oversized responses" do
      large_response = "x" * (AuthProto::HttpClient::MAX_RESPONSE_SIZE + 1)

      stub_request(:get, sample_url)
        .to_return(status: 200, body: large_response)

      assert_raises(AuthProto::HttpClient::HttpError) do
        client.get(sample_url)
      end
    end
  end

  describe "#post" do
    let(:post_body) { "request body" }
    let(:post_headers) { { "Content-Type" => "text/plain" } }

    before do
      stub_request(:post, sample_url)
        .to_return(status: 201, body: "created")
    end

    it "makes successful POST requests" do
      response = client.post(sample_url, body: post_body, headers: post_headers)
      assert_equal 201, response[:status]
      assert_equal "created", response[:body]
    end

    it "sends request body" do
      stub_request(:post, sample_url)
        .with(body: post_body)
        .to_return(status: 201)

      client.post(sample_url, body: post_body)
      assert_requested :post, sample_url, body: post_body
    end

    it "handles POST redirects" do
      redirect_url = "https://example.com/final"

      stub_request(:post, sample_url)
        .with(body: post_body)
        .to_return(status: 307, headers: { "Location" => redirect_url })
      stub_request(:post, redirect_url)
        .with(body: post_body)
        .to_return(status: 201, body: "redirected")

      response = client.post(sample_url, body: post_body)
      assert_equal "redirected", response[:body]
      assert_requested :post, redirect_url, body: post_body
    end
    #
    # it "handles POST redirects" do
    #   redirect_url = "https://example.com/final"
    #
    #   stub_request(:post, sample_url).
    #     to_return(status: 307, headers: {"Location" => redirect_url})
    #   stub_request(:post, redirect_url).
    #     to_return(status: 201, body: "redirected")
    #
    #   response = client.post(sample_url, body: post_body)
    #   assert_equal "redirected", response[:body]
    #   assert_requested :post, redirect_url
    # end

    it "includes security headers in POST requests" do
      stub_request(:post, sample_url)
        .with(headers: { "Cache-Control" => "no-store" })
        .to_return(status: 201)

      client.post(sample_url)
      assert_requested :post, sample_url, headers: { "Cache-Control" => "no-store" }
    end
  end

  describe "timeout handling" do
    let(:client) { AuthProto::HttpClient.new(timeout: 1) }

    it "handles read timeouts" do
      stub_request(:get, sample_url).to_timeout

      assert_raises(AuthProto::HttpClient::HttpError) do
        client.get(sample_url)
      end
    end
  end

  describe "SSL verification" do
    it "verifies SSL certificates by default" do
      client = AuthProto::HttpClient.new
      http = Net::HTTP.new("example.com")
      client.send(:configure_http_client!, http)
      assert_equal OpenSSL::SSL::VERIFY_PEER, http.verify_mode
    end

    it "can disable SSL verification" do
      client = AuthProto::HttpClient.new(verify_ssl: false)
      http = Net::HTTP.new("example.com")
      client.send(:configure_http_client!, http)
      assert_equal OpenSSL::SSL::VERIFY_NONE, http.verify_mode
    end
  end
end
