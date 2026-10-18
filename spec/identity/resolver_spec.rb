# frozen_string_literal: true

require 'json'
require 'resolv'

describe AuthProto::Identity::Resolver do
  let(:resolver) { AuthProto::Identity::Resolver.new }
  let(:handle) { "user.test.com" }
  let(:did) { "did:plc:test123" }
  let(:pds_url) { "https://pds.test.com" }

  before do
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
    AuthProto.configure do |configuration|
      configuration.http_client = AuthProto::HttpClient.new
    end
  end

  describe "#resolve_handle" do
    it "should resolve handle via DNS" do
      mock_dns = mock("DNS resolver")
      mock_dns.stubs(:timeouts=)
      mock_dns.stubs(:close)
      mock_dns.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
      txt_record = mock("TXT record", strings: ["did=did:plc:test123"])
      mock_dns.stubs(:getresources).returns([])
      mock_dns.expects(:getresources).with("_atproto.user.test.com", Resolv::DNS::Resource::IN::TXT).returns([txt_record])
      Resolv::DNS.stubs(:new).returns(mock_dns)
      stub_plc_document(did, pds_url)

      result = resolver.resolve_handle(handle)
      result[:did].should == did
      result[:pds].should == pds_url
    end

    it "should fall back to HTTP resolution when DNS fails" do
      stub_dns_empty do
        stub_request(:get, "https://#{handle}/.well-known/atproto-did")
          .to_return(
            status: 200,
            body: did,
            headers: { "Content-Type": "text/plain" }
          )

        stub_plc_document(did, pds_url)

        result = resolver.resolve_handle(handle)
        result[:did].should == did
        result[:pds].should == pds_url
      end
    end

    it "should handle @ prefix in handle" do
      result = resolver.send(:normalize_handle, "@user.test.com")
      result.should == "user.test.com"
    end

    it "should validate handle format" do
      expect {
        resolver.resolve_handle("invalid handle")
      }.to raise_error(AuthProto::Identity::ResolutionError)
    end
  end

  describe "#get_did_info" do
    it "should fetch and validate DID document" do
      stub_plc_document(did, pds_url)

      result = resolver.get_did_info(did)
      result[:did].should == did
      result[:pds].should == pds_url
      result[:document].should be_a(AuthProto::Identity::Document)
    end

    it "should require HTTPS for PDS URL" do
      stub_plc_document(did, "http://insecure.com")

      expect {
        resolver.get_did_info(did)
      }.to raise_error(AuthProto::Identity::ResolutionError)
    end

    it "should validate DID format" do
      expect {
        resolver.get_did_info("invalid:did")
      }.to raise_error(AuthProto::Identity::ResolutionError)
    end

    it "should fetch and validate web DID document" do
      web_did = "did:web:example.com"
      stub_request(:get, "https://example.com/.well-known/did.json")
        .to_return(
          status: 200,
          body: {
            id: web_did,
            pds: "https://pds.example.com"
          }.to_json,
          headers: { "Content-Type": "application/json" }
        )

      result = resolver.get_did_info(web_did)
      result[:did].should == web_did
      result[:pds].should == "https://pds.example.com"
    end

    it "should handle web DID with path component" do
      web_did = "did:web:example.com:user:alice"
      stub_request(:get, "https://example.com/user/alice/did.json")
        .to_return(
          status: 200,
          body: {
            id: web_did,
            pds: "https://pds.example.com"
          }.to_json,
          headers: { "Content-Type": "application/json" }
        )

      result = resolver.get_did_info(web_did)
      result[:did].should == web_did
    end
  end

  describe "#verify_pds_binding" do
    it "should verify PDS hosts DID" do
      stub_plc_document(did, pds_url)

      (resolver.verify_pds_binding(did, pds_url)).should be_truthy
    end

    it "should normalize URLs for comparison" do
      stub_plc_document(did, pds_url)

      (resolver.verify_pds_binding(did, "#{pds_url}/")).should be_truthy
    end

    it "should raise error for non-matching PDS" do
      stub_plc_document(did, pds_url)
      different_pds = "https://different-pds.com"

      expect {
        resolver.verify_pds_binding(did, different_pds)
      }.to raise_error(AuthProto::Identity::ValidationError) { |error|
        error.message.should match(/PDS .* is not authorized for DID .*/)
      }
    end
  end

  describe "#verify_issuer_binding" do
    let(:issuer) { "https://auth.test.com" }

    it "should verify issuer is authorized for DID" do
      stub_plc_document(did, pds_url)
      stub_resource_server_metadata(pds_url, issuer)

      (resolver.verify_issuer_binding(did, issuer)).should be_truthy
    end

    it "should normalize URLs for comparison" do
      stub_plc_document(did, pds_url)
      stub_resource_server_metadata(pds_url, issuer)

      (resolver.verify_issuer_binding(did, "#{issuer}/")).should be_truthy
    end

    it "should fail for non-matching issuer" do
      stub_plc_document(did, pds_url)
      stub_resource_server_metadata(pds_url, issuer)

      expect {
        resolver.verify_issuer_binding(did, "https://wrong-issuer.com")
      }.to raise_error(AuthProto::Identity::ValidationError) { |error|
        error.message.should match(/Issuer .* is not authorized for DID .*/)
      }
    end
  end

  describe "#verify_handle_binding" do
    it "should verify handle belongs to DID" do
      doc = {
        "id" => did,
        "alsoKnownAs" => ["at://#{handle}"],
        "pds" => pds_url
      }
      stub_request(:get, "#{resolver.instance_variable_get(:@plc_directory)}/#{did}")
        .to_return(
          status: 200,
          body: doc.to_json,
          headers: { "Content-Type": "application/json" }
        )

      (resolver.verify_handle_binding(handle, did)).should be_truthy
    end

    it "should fail for non-matching handle" do
      doc = {
        "id" => did,
        "alsoKnownAs" => ["at://other.handle.com"],
        "pds" => pds_url
      }
      stub_request(:get, "#{resolver.instance_variable_get(:@plc_directory)}/#{did}")
        .to_return(
          status: 200,
          body: doc.to_json,
          headers: { "Content-Type": "application/json" }
        )

      expect {
        resolver.verify_handle_binding(handle, did)
      }.to raise_error(AuthProto::Identity::ValidationError) { |error|
        error.message.should match(/Handle .* does not belong to DID .*/)
      }
    end
  end

  private

  def stub_dns_empty(&block)
    Resolv::DNS.any_instance.stubs(:getresources).returns([])
    block&.call
  end

  def stub_plc_document(did, pds_url)
    stub_request(:get, "#{resolver.instance_variable_get(:@plc_directory)}/#{did}")
      .to_return(
        status: 200,
        body: {
          "id" => did,
          "pds" => pds_url
        }.to_json,
        headers: { "Content-Type": "application/json" }
      )
  end

  def stub_resource_server_metadata(pds_url, auth_server)
    stub_request(:get, "#{pds_url}/.well-known/oauth-protected-resource")
      .to_return(
        status: 200,
        body: {
          authorization_servers: [auth_server]
        }.to_json,
        headers: { "Content-Type": "application/json" }
      )
  end
end
