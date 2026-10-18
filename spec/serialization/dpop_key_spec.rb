# frozen_string_literal: true

require 'json'

describe AuthProto::Serialization::DPoPKey do
  let(:key_manager) { AuthProto::DPoP::KeyManager.new }
  let(:serializer) { AuthProto::Serialization::DPoPKey.new }

  it "should roundtrip a DPoP key manager object" do
    serialized = serializer.serialize(key_manager)
    deserialized = serializer.deserialize(serialized)

    # Compare public key components
    original_jwk = key_manager.public_jwk
    deserialized_jwk = deserialized.public_jwk

    deserialized_jwk["kty"].should == original_jwk["kty"]
    deserialized_jwk["crv"].should == original_jwk["crv"]
    deserialized_jwk["x"].should == original_jwk["x"]
    deserialized_jwk["y"].should == original_jwk["y"]
  end

  it "should encrypt private key material" do
    serialized = JSON.parse(serializer.serialize(key_manager))
    jwk = serialized["data"]

    jwk["d"].should be_encrypted if jwk["d"] # Private key component
  end

  it "should validate object type" do
    expect {
      serializer.serialize(Object.new)
    }.to raise_error(AuthProto::Serialization::ValidationError)
  end
end
