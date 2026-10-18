# frozen_string_literal: true

describe AuthProto::PAR::Response do
  describe "#initialize" do
    it "should initialize with valid parameters" do
      response = AuthProto::PAR::Response.new(request_uri: "https://example.com/request", expires_in: 3600)
      response.request_uri.should == "https://example.com/request"
      response.expires_in.should == 3600
    end

    it "should raise an error if request_uri is missing" do
      expect {
        AuthProto::PAR::Response.new(request_uri: nil, expires_in: 3600)
      }.to raise_error(AuthProto::PAR::Error)
    end

    it "should raise an error if request_uri is empty" do
      expect {
        AuthProto::PAR::Response.new(request_uri: "", expires_in: 3600)
      }.to raise_error(AuthProto::PAR::Error)
    end

    it "should raise an error if expires_in is not positive" do
      expect {
        AuthProto::PAR::Response.new(request_uri: "https://example.com/request", expires_in: 0)
      }.to raise_error(AuthProto::PAR::Error)
    end
  end
end
