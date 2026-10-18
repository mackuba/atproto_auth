# frozen_string_literal: true

require_relative '../test_helper'
require 'atproto_auth/minisky_oauth'

describe MiniskyOAuth do
  let(:host) { "https://pds.example.com" }
  let(:endpoint) { "#{host}/xrpc/app.bsky.actor.getProfile" }
  let(:client_metadata) do
    {
      "client_id" => "https://client.example.com/metadata.json",
      "redirect_uris" => ["https://client.example.com/callback"],
      "grant_types" => %w[authorization_code refresh_token],
      "response_types" => ["code"],
      "scope" => "atproto",
      "dpop_bound_access_tokens" => true,
      "application_type" => "web"
    }
  end
  let(:client) do
    MiniskyOAuth.new(
      host, client_id: client_metadata["client_id"], redirect_uri: client_metadata["redirect_uris"].first,
            metadata: client_metadata
    )
  end
  let(:auth_server) do
    AuthProto::ServerMetadata::AuthorizationServer.new(
      "issuer" => "https://auth.example.com",
      "token_endpoint" => "https://auth.example.com/token",
      "authorization_endpoint" => "https://auth.example.com/authorize",
      "response_types_supported" => "code",
      "grant_types_supported" => %w[authorization_code refresh_token],
      "code_challenge_methods_supported" => "S256",
      "token_endpoint_auth_methods_supported" => %w[private_key_jwt none],
      "token_endpoint_auth_signing_alg_values_supported" => ["ES256"],
      "scopes_supported" => ["atproto"],
      "dpop_signing_alg_values_supported" => ["ES256"],
      "pushed_authorization_request_endpoint" => "https://auth.example.com/par",
      "authorization_response_iss_parameter_supported" => true,
      "require_pushed_authorization_requests" => true,
      "client_id_metadata_document_supported" => true
    )
  end

  before do
    @previous_configuration = AuthProto.configuration
    AuthProto.reset_configuration!
    AuthProto.configuration.http_client = AuthProto::HttpClient.new
  end

  after do
    AuthProto.configuration = @previous_configuration
  end

  def token_set(expires_in: 3600)
    AuthProto::State::TokenSet.new(access_token: "access", refresh_token: "refresh", token_type: "DPoP",
                                     expires_in: expires_in, scope: "atproto", sub: "did:plc:alice")
  end

  def attach_session(expires_in: 3600)
    session = client.oauth_client.session_manager.create_session(
      client_id: client_metadata["client_id"], scope: "atproto", auth_server: auth_server
    )
    session.tokens = token_set(expires_in: expires_in)
    client.oauth_client.session_manager.update_session(session)
    client.instance_variable_set(:@session_id, session.session_id)
    session
  end

  def response_headers(nonce = "pds-nonce")
    { "Content-Type" => "application/json", "DPoP-Nonce" => nonce }
  end

  def stub_refresh
    # HttpClient validates DNS before the mocked HTTP request.
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
    stub_request(:post, "https://auth.example.com/token").with do |request|
      URI.decode_www_form(request.body).to_h["grant_type"] == "refresh_token"
    end.to_return(status: 200, headers: response_headers("auth-nonce"), body: {
      access_token: "new-access", refresh_token: "new-refresh", token_type: "DPoP",
      expires_in: 3600, scope: "atproto", sub: "did:plc:alice"
    }.to_json)
  end

  def stub_authorization_metadata
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
    stub_request(:get, "#{host}/.well-known/oauth-protected-resource")
      .to_return(status: 200, body: { authorization_servers: [auth_server.issuer] }.to_json)
    stub_request(:get, "#{auth_server.issuer}/.well-known/oauth-authorization-server")
      .to_return(status: 200, body: auth_server.to_h.to_json)
  end

  it "authorizes a localhost public client using PKCE and DPoP without a client assertion" do
    client_metadata["client_id"] = "http://localhost/"
    client_metadata["redirect_uris"] = ["http://127.0.0.1:9292/callback"]
    client_metadata["token_endpoint_auth_method"] = "none"
    stub_authorization_metadata
    AuthProto::PAR::ClientAssertion.expects(:new).never
    stub_request(:post, "#{auth_server.issuer}/par").with do |request|
      form = URI.decode_www_form(request.body).to_h
      form["client_id"] == "http://localhost/" && form["code_challenge_method"] == "S256" &&
        !form.key?("client_assertion") && !form.key?("client_assertion_type") && request.headers.key?("Dpop")
    end.to_return(status: 201, body: { request_uri: "urn:example:par", expires_in: 90 }.to_json)

    result = client.authorize(pds_url: host)
    _(URI(result[:url]).host).must_equal "auth.example.com"
    _(client.session_id).must_equal result[:session_id]
  end

  it "includes a verifiable client assertion when authorizing a confidential client" do
    key = JOSE::JWK.generate_key([:ec, "P-256"])
    key_data = key.to_map.to_h.merge("kid" => "client-key", "use" => "sig")
    client_metadata.merge!("token_endpoint_auth_method" => "private_key_jwt",
                           "token_endpoint_auth_signing_alg" => "ES256", "jwks" => { "keys" => [key_data] })
    stub_authorization_metadata
    public_key = JWT::JWK.import(key.to_public.to_map.to_h).public_key
    stub_request(:post, "#{auth_server.issuer}/par").with do |request|
      form = URI.decode_www_form(request.body).to_h
      payload, header = JWT.decode(form.fetch("client_assertion"), public_key, true, algorithm: "ES256")
      payload["iss"] == client_metadata["client_id"] && payload["aud"] == auth_server.issuer &&
        header["kid"] == "client-key" && form["client_assertion_type"] == AuthProto::PAR::CLIENT_ASSERTION_TYPE
    end.to_return(status: 201, body: { request_uri: "urn:example:par", expires_in: 90 }.to_json)

    _(client.authorize(pds_url: host)[:url]).must_include "urn%3Aexample%3Apar"
  end

  it "disables Minisky password token management" do
    _(client.auto_manage_tokens).must_equal false
    _(client.send_auth_headers).must_equal true
    _(client.config).must_be_nil
  end

  it "retains existing memory sessions when another client is created" do
    session = attach_session
    MiniskyOAuth.new(
      host, client_id: client_metadata["client_id"], redirect_uri: client_metadata["redirect_uris"].first,
            metadata: client_metadata
    )
    _(client.oauth_client.session_manager.get_session(session.session_id)).wont_be_nil
  end

  it "delegates login and remembers the callback session" do
    client.oauth_client.expects(:authorize).with(handle: "alice.example.com")
          .returns(url: "https://auth.example.com/authorize", session_id: "pending")
    _(client.authorize(handle: "alice.example.com")[:session_id]).must_equal "pending"
    _(client.session_id).must_equal "pending"
    client.oauth_client.expects(:handle_callback).with(code: "code", state: "state", iss: "issuer")
          .returns(session_id: "authorized")
    client.handle_callback(code: "code", state: "state", iss: "issuer")
    _(client.session_id).must_equal "authorized"
  end

  it "signs GETs, preserves params and custom headers, and saves successful response nonces" do
    attach_session
    stub_request(:get, endpoint).with(query: { actor: "alice.example.com" }, headers: {
                                        "Authorization" => "DPoP access", "X-Test" => "yes"
                                      }) do |request|
      payload = JWT.decode(request.headers["Dpop"], nil, false).first
      payload["htm"] == "GET" && payload["htu"] == endpoint && payload.key?("ath")
    end.to_return(status: 200, headers: response_headers, body: '{"did":"did:plc:alice"}')

    result = client.get_request("app.bsky.actor.getProfile", { actor: "alice.example.com" },
                                headers: { "X-Test" => "yes", "authorization" => "Bearer wrong" })
    _(result["did"]).must_equal "did:plc:alice"
    _(client.oauth_client.dpop_client.nonce_manager.get(host)).must_equal "pds-nonce"
  end

  it "allows unauthenticated requests without a session or nonce header" do
    stub_request(:get, endpoint).with { |request| !request.headers.key?("Authorization") }
                                .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")
    _(client.get_request("app.bsky.actor.getProfile", auth: false)).must_equal({})
  end

  it "rejects authenticated requests before login" do
    _(-> { client.get_request("app.bsky.actor.getProfile") }).must_raise Minisky::AuthError
  end

  it "returns :ok from check_access when no refresh is needed" do
    attach_session
    client.oauth_client.expects(:refresh_token).never
    _(client.check_access).must_equal :ok
  end

  it "returns :refreshed from check_access after refreshing expired tokens" do
    attach_session(expires_in: -10)
    stub_refresh
    _(client.check_access).must_equal :refreshed
    _(client.oauth_client.get_tokens(client.session_id)[:access_token]).must_equal "new-access"
  end

  it "raises from check_access when OAuth login has not completed" do
    _(-> { client.check_access }).must_raise Minisky::AuthError
  end

  it "refreshes an expired token and stores the rotated tokens before sending the GET" do
    attach_session(expires_in: -10)
    stub_refresh
    stub_request(:get, endpoint).with(headers: { "Authorization" => "DPoP new-access" })
                                .to_return(status: 200, headers: response_headers, body: "{}")
    client.get_request("app.bsky.actor.getProfile")
    _(client.oauth_client.get_tokens(client.session_id)[:refresh_token]).must_equal "new-refresh"
  end

  it "retries a nonce challenge with a fresh proof and the new nonce" do
    attach_session
    proofs = []
    stub_request(:get, endpoint).to_return do |request|
      proofs << request.headers["Dpop"]
      payload = JWT.decode(proofs.last, nil, false).first
      if proofs.length == 1
        { status: 401, headers: response_headers("challenge").merge(
          "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
        ), body: "{}" }
      else
        _(payload["nonce"]).must_equal "challenge"
        { status: 200, headers: response_headers("next-nonce"), body: "{}" }
      end
    end
    client.get_request("app.bsky.actor.getProfile")
    _(proofs.uniq.length).must_equal 2
  end

  it "stops after two nonce retries and preserves Minisky's API error" do
    attach_session
    stub_request(:get, endpoint).to_return(status: 401, headers: response_headers.merge(
      "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
    ), body: '{"error":"use_dpop_nonce"}')
    _(-> { client.get_request("app.bsky.actor.getProfile") }).must_raise Minisky::ClientErrorResponse
    assert_requested :get, endpoint, times: 3
  end

  it "refreshes once after invalid_token and stops if the token is still rejected" do
    attach_session
    stub_refresh
    stub_request(:get, endpoint).to_return(status: 401, headers: response_headers.merge(
      "WWW-Authenticate" => 'DPoP error="invalid_token"'
    ), body: '{"error":"invalid_token"}')
    _(-> { client.get_request("app.bsky.actor.getProfile") }).must_raise Minisky::ClientErrorResponse
    assert_requested :get, endpoint, times: 2
    assert_requested :post, "https://auth.example.com/token", times: 1
  end

  it "does not refresh for permission errors" do
    attach_session
    client.oauth_client.expects(:refresh_token).never
    stub_request(:get, endpoint).to_return(status: 403, headers: response_headers,
                                           body: '{"error":"Forbidden"}')
    error = _(-> { client.get_request("app.bsky.actor.getProfile") }).must_raise Minisky::ClientErrorResponse
    _(error.error_type).must_equal "Forbidden"
  end

  it "does not retry a transport timeout" do
    attach_session
    stub_request(:get, endpoint).to_timeout
    _(-> { client.get_request("app.bsky.actor.getProfile") }).must_raise Net::OpenTimeout
    assert_requested :get, endpoint, times: 1
  end

  it "accepts successful authenticated responses without a nonce and retains the cached nonce" do
    attach_session
    client.oauth_client.dpop_client.nonce_manager.update(nonce: "cached", server_url: host)
    stub_request(:get, endpoint).to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")
    _(client.get_request("app.bsky.actor.getProfile")).must_equal({})
    _(client.oauth_client.dpop_client.nonce_manager.get(host)).must_equal "cached"
  end

  it "rejects nonce challenges without a nonce instead of retrying" do
    attach_session
    stub_request(:get, endpoint).to_return(status: 401, headers: {
                                             "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
                                           }, body: "{}")
    _(-> { client.get_request("app.bsky.actor.getProfile") }).must_raise AuthProto::DPoP::Client::Error
    assert_requested :get, endpoint, times: 1
  end

  it "preserves API errors without a nonce" do
    attach_session
    stub_request(:get, endpoint).to_return(status: 403, headers: { "Content-Type" => "application/json" },
                                           body: '{"error":"Forbidden"}')
    error = _(-> { client.get_request("app.bsky.actor.getProfile") }).must_raise Minisky::ClientErrorResponse
    _(error.error_type).must_equal "Forbidden"
  end

  it "supports fetch_all with separate proofs for each page" do
    attach_session
    proofs = []
    stub_request(:get, endpoint).to_return do |request|
      proofs << request.headers["Dpop"]
      { status: 200, headers: response_headers,
        body: { records: [proofs.length], cursor: proofs.length == 1 ? "next" : nil }.to_json }
    end
    stub_request(:get, endpoint).with(query: { cursor: "next" }).to_return do |request|
      proofs << request.headers["Dpop"]
      { status: 200, headers: response_headers, body: '{"records":[2]}' }
    end
    _(client.fetch_all("app.bsky.actor.getProfile", field: "records")).must_equal [1, 2]
    _(proofs.uniq.length).must_equal 2
  end

  it "explicitly disables app-password login" do
    _(-> { client.log_in }).must_raise NotImplementedError
  end

  describe "POST requests" do
    let(:rpc_method) { "com.atproto.repo.createRecord" }
    let(:post_endpoint) { "#{host}/xrpc/#{rpc_method}" }
    let(:record) { { repo: "did:plc:alice", collection: "app.bsky.feed.post", record: { text: "Hello" } } }

    it "sends JSON with a POST proof and accepts a successful response without a nonce" do
      attach_session
      expected_headers = {
        "Content-Type" => "application/json", "Authorization" => "DPoP access", "X-Test" => "yes"
      }
      stub_request(:post, post_endpoint).with(body: record.to_json, headers: expected_headers) do |request|
        payload = JWT.decode(request.headers["Dpop"], nil, false).first
        payload["htm"] == "POST" && payload["htu"] == post_endpoint && payload.key?("ath")
      end.to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: '{"uri":"at://record"}')

      headers = { "X-Test" => "yes", "authorization" => "Bearer wrong" }
      _(client.post_request(rpc_method, record, headers: headers)["uri"]).must_equal "at://record"
      _(headers).must_equal("X-Test" => "yes", "authorization" => "Bearer wrong")
    end

    it "preserves a binary body, query and custom content type across a nonce retry" do
      attach_session
      binary = "\x00\xFF\x80".b
      proofs = []
      binary_headers = { "Content-Type" => "application/octet-stream" }
      stub_request(:post, post_endpoint).with(query: { test: "yes" }, body: binary,
                                              headers: binary_headers).to_return do |req|
        proofs << req.headers["Dpop"]
        proof = JWT.decode(proofs.last, nil, false).first
        _(proof["htu"]).must_equal post_endpoint
        if proofs.length == 1
          { status: 401, headers: response_headers("challenge").merge(
            "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
          ), body: "{}" }
        else
          _(proof["nonce"]).must_equal "challenge"
          { status: 200, headers: response_headers("next-nonce"), body: "{}" }
        end
      end

      client.post_request(URI(post_endpoint), binary, params: { test: "yes" },
                                                      headers: { "content-type" => "application/octet-stream" })
      _(proofs.uniq.length).must_equal 2
      _(client.oauth_client.dpop_client.nonce_manager.get(host)).must_equal "next-nonce"
    end

    it "refreshes an expired token before posting" do
      attach_session(expires_in: -10)
      stub_refresh
      stub_request(:post, post_endpoint).with(headers: { "Authorization" => "DPoP new-access" }, body: record.to_json)
                                        .to_return(status: 200, headers: response_headers, body: "{}")
      client.post_request(rpc_method, record)
    end

    it "refreshes once after an invalid_token rejection and retries the same body" do
      attach_session
      stub_refresh
      stub_request(:post, post_endpoint).with(headers: { "Authorization" => "DPoP access" }, body: record.to_json)
                                        .to_return(status: 401, headers: {
                                                     "WWW-Authenticate" => 'DPoP error="invalid_token"'
                                                   }, body: "{}")
      stub_request(:post, post_endpoint).with(headers: { "Authorization" => "DPoP new-access" }, body: record.to_json)
                                        .to_return(status: 200, headers: response_headers, body: "{}")
      client.post_request(rpc_method, record)
      assert_requested :post, post_endpoint, times: 2
      assert_requested :post, "https://auth.example.com/token", times: 1
    end

    it "allows unauthenticated JSON posts without a session" do
      stub_request(:post, post_endpoint).with(body: record.to_json) do |request|
        !request.headers.key?("Authorization") && !request.headers.key?("Dpop")
      end.to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")
      _(client.post_request(rpc_method, record, auth: false)).must_equal({})
    end

    it "allows an omitted body" do
      attach_session
      stub_request(:post, post_endpoint).with(body: "")
                                        .to_return(status: 200, headers: response_headers, body: "{}")
      client.post_request(rpc_method)
    end

    it "does not retry after a transport timeout" do
      attach_session
      stub_request(:post, post_endpoint).to_timeout
      _(-> { client.post_request(rpc_method, record) }).must_raise Net::OpenTimeout
      assert_requested :post, post_endpoint, times: 1
    end

    it "preserves server errors without retrying or requiring a nonce" do
      attach_session
      stub_request(:post, post_endpoint).to_return(status: 500, headers: { "Content-Type" => "application/json" },
                                                   body: '{"error":"InternalServerError"}')
      error = _(-> { client.post_request(rpc_method, record) }).must_raise Minisky::ServerErrorResponse
      _(error.error_type).must_equal "InternalServerError"
      assert_requested :post, post_endpoint, times: 1
    end
  end
end
