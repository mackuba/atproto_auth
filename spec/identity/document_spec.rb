# frozen_string_literal: true

describe AuthProto::Identity::Document do
  let(:valid_data) do
    {
      "id" => "did:plc:abc123",
      "verificationMethod" => [{ "publicKeyMultibase" => "z123" }],
      "alsoKnownAs" => ["at://alice.example.com"],
      "pds" => "https://pds.example.com"
    }
  end

  let(:legacy_data) do
    {
      "id" => "did:plc:abc123",
      "service" => [
        {
          "id" => "#atproto_pds",
          "type" => "AtprotoPersonalDataServer",
          "serviceEndpoint" => "https://pds.example.com"
        }
      ]
    }
  end

  let(:invalid_data_no_id) { { "verificationMethod" => [] } }
  let(:invalid_did) { { "id" => "invalid:plc:123" } }
  let(:invalid_service_format) do
    {
      "id" => "did:plc:abc123",
      "service" => [{ "id" => "#svc", "type" => "ServiceType" }]
    }
  end

  describe "#initialize" do
    it "should initialize with valid data" do
      doc = AuthProto::Identity::Document.new(valid_data)
      doc.did.should == "did:plc:abc123"
      doc.rotation_keys.should == ["z123"]
      doc.also_known_as.should == ["at://alice.example.com"]
      doc.pds.should == "https://pds.example.com"
    end

    it "should initialize with legacy data format" do
      doc = AuthProto::Identity::Document.new(legacy_data)
      doc.did.should == "did:plc:abc123"
      doc.rotation_keys.should == []
      doc.also_known_as.should == []
      doc.pds.should == "https://pds.example.com"
    end

    it "should raise an error if data is missing id" do
      expect {
        AuthProto::Identity::Document.new(invalid_data_no_id)
      }.to raise_error(AuthProto::Identity::DocumentError)
    end

    it "should raise an error if DID format is invalid" do
      expect {
        AuthProto::Identity::Document.new(invalid_did)
      }.to raise_error(AuthProto::Identity::Error)
    end

    it "should raise an error if service entry format is invalid" do
      expect {
        AuthProto::Identity::Document.new(invalid_service_format)
      }.to raise_error(AuthProto::Identity::DocumentError)
    end
  end

  describe "#has_handle?" do
    let(:doc) { AuthProto::Identity::Document.new(valid_data) }

    it "should return true if handle is present in alsoKnownAs" do
      doc.has_handle?("alice.example.com").should be true
    end

    it "should return true if handle with @ prefix is present in alsoKnownAs" do
      doc.has_handle?("@alice.example.com").should be true
    end

    it "should return false if handle is not present in alsoKnownAs" do
      doc.has_handle?("bob.example.com").should be false
    end
  end
end
