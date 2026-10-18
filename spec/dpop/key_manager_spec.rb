# frozen_string_literal: true

describe AuthProto::DPoP::KeyManager do
  let(:valid_keypair) { JOSE::JWK.generate_key([:ec, "P-256"]) }
  let(:invalid_keypair) { JOSE::JWK.generate_key([:rsa, 2048]) }

  describe "#initialize" do
    it "should create a KeyManager with a valid EC keypair" do
      manager = AuthProto::DPoP::KeyManager.new(valid_keypair)
      manager.keypair.should == valid_keypair
    end

    it "should raise an error when initialized with an invalid keypair" do
      expect {
        AuthProto::DPoP::KeyManager.new(invalid_keypair)
      }.to raise_error(AuthProto::DPoP::KeyManager::KeyError)
    end

    it "should generate a new keypair if none is provided" do
      manager = AuthProto::DPoP::KeyManager.new
      keypair = manager.keypair
      keypair.to_map["kty"].should == "EC"
      keypair.to_map["crv"].should == "P-256"
    end
  end

  describe "#generate_keypair" do
    it "should generate a valid ES256 keypair" do
      manager = AuthProto::DPoP::KeyManager.new
      keypair = manager.generate_keypair
      keypair.to_map["kty"].should == "EC"
      keypair.to_map["crv"].should == "P-256"
    end
  end

  describe "#public_jwk" do
    it "should return the public key in JWK format" do
      manager = AuthProto::DPoP::KeyManager.new(valid_keypair)
      public_jwk = manager.public_jwk
      public_jwk["kty"].should == "EC"
      public_jwk["crv"].should == "P-256"
    end
  end

  describe "#sign" do
    it "should sign data using the private key" do
      manager = AuthProto::DPoP::KeyManager.new(valid_keypair)
      data = "test_data"
      signature = manager.sign(data)
      signature.should be_an_instance_of(JOSE::SignedBinary)
    end
  end

  describe "#verify" do
    it "should verify a signed JWS" do
      manager = AuthProto::DPoP::KeyManager.new(valid_keypair)
      data = "test_data"
      signature = manager.sign(data)
      (manager.verify(signature)).should be_truthy
    end

    it "should raise an error if verification fails" do
      manager = AuthProto::DPoP::KeyManager.new(valid_keypair)
      invalid_signature = "invalid_signature"
      expect {
        manager.verify(invalid_signature)
      }.to raise_error(AuthProto::DPoP::KeyManager::KeyError)
    end
  end

  describe "#to_jwk" do
    it "should export the keypair in JWK format including private key" do
      manager = AuthProto::DPoP::KeyManager.new(valid_keypair)
      jwk = manager.to_jwk(include_private: true)
      jwk["kty"].should == "EC"
      jwk["crv"].should == "P-256"
      (jwk.key?("d")).should be_truthy
    end

    it "should export the public key only when include_private is false" do
      manager = AuthProto::DPoP::KeyManager.new(valid_keypair)
      jwk = manager.to_jwk(include_private: false)
      jwk["kty"].should == "EC"
      jwk["crv"].should == "P-256"
      (jwk.key?("d")).should be_falsey
    end
  end

  describe ".from_jwk" do
    it "should create a KeyManager instance from a JWK" do
      manager = AuthProto::DPoP::KeyManager.from_jwk(valid_keypair.to_map)
      manager.should be_an_instance_of(AuthProto::DPoP::KeyManager)
    end

    it "should raise an error if importing the JWK fails" do
      invalid_jwk = { "kty" => "RSA", "n" => "mocked_n", "e" => "mocked_e" }
      expect {
        AuthProto::DPoP::KeyManager.from_jwk(invalid_jwk)
      }.to raise_error(AuthProto::DPoP::KeyManager::KeyError)
    end
  end
end
