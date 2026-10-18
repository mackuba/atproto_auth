# frozen_string_literal: true

describe AuthProto::Identity::DID do
  describe "#initialize" do
    it "should initialize with a DID" do
      did = AuthProto::Identity::DID.new("did:plc:abc123")
      did.to_s.should == "did:plc:abc123"
    end
  end

  describe "#validate!" do
    it "should validate a PLC DID" do
      did = AuthProto::Identity::DID.new("did:plc:abc123")
      did.validate!
    end

    it "should validate a Web DID" do
      did = AuthProto::Identity::DID.new("did:web:abc123")
      did.validate!
    end

    it "should raise an error for an invalid DID" do
      did = AuthProto::Identity::DID.new("invalid:plc:123")
      expect {
        did.validate!
      }.to raise_error(AuthProto::Identity::Error)
    end
  end
end
