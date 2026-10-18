# frozen_string_literal: true

require_relative '../../test_helper'

describe AuthProto::PAR::ClientAssertion do
  let(:client_id) { "test-client-id" }
  let(:audience) { "https://example.com/oauth/token" }
  let(:signing_key) do
    base_key = JOSE::JWK.generate_key([:ec, "P-256"])
    base_map = base_key.to_map

    key_map = {
      "kty" => base_map["kty"],
      "crv" => base_map["crv"],
      "x" => base_map["x"],
      "y" => base_map["y"],
      "d" => base_map["d"],
      "use" => "sig",
      "kid" => "test-key-id"
    }

    JOSE::JWK.from_map(key_map)
  end
  let(:client_assertion) { AuthProto::PAR::ClientAssertion.new(client_id: client_id, signing_key: signing_key) }

  describe "#generate_jwt" do
    it "generates a valid JWT assertion" do
      lifetime = 300
      now = Time.now.to_i
      Time.stubs(:now).returns(Time.at(now)) # Stub Time.now for predictable timestamps

      jwt = client_assertion.generate_jwt(audience: audience, lifetime: lifetime)
      public_key = JWT::JWK.import(signing_key.to_public.to_map.to_h).public_key
      decoded, header = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })

      # Verify claims
      _(decoded["iss"]).must_equal client_id
      _(decoded["sub"]).must_equal client_id
      _(decoded["aud"]).must_equal audience
      _(decoded["jti"]).wont_be_nil
      _(decoded["iat"]).must_equal now
      _(decoded["exp"]).must_equal now + lifetime

      # Verify header
      _(header["alg"]).must_equal "ES256"
      _(header["typ"]).must_equal "JWT"
      _(header["kid"]).must_equal "test-key-id"
    end

    it "raises an error if signing fails" do
      signing_key.stubs(:to_map).raises(ArgumentError, "Invalid key")

      error = assert_raises(AuthProto::PAR::ClientAssertion::Error) do
        client_assertion.generate_jwt(audience: audience)
      end

      _(error.message).must_match(/Failed to generate client assertion/)
    end

    it "wraps JWT signing errors when only a public key is supplied" do
      assertion = AuthProto::PAR::ClientAssertion.new(client_id: client_id, signing_key: signing_key.to_public)
      error = assert_raises(AuthProto::PAR::ClientAssertion::Error) do
        assertion.generate_jwt(audience: audience)
      end

      _(error.cause).must_be_kind_of JWT::EncodeError
    end

    it "rejects a signing key whose curve does not match ES256" do
      assertion = AuthProto::PAR::ClientAssertion.new(
        client_id: client_id, signing_key: JOSE::JWK.generate_key([:ec, "P-384"])
      )
      error = assert_raises(AuthProto::PAR::ClientAssertion::Error) do
        assertion.generate_jwt(audience: audience)
      end

      _(error.cause).must_be_kind_of JWT::EncodeError
    end

    it "rejects a JWK algorithm that conflicts with ES256" do
      key = JOSE::JWK.from_map(signing_key.to_map.to_h.merge("alg" => "ES384"))
      assertion = AuthProto::PAR::ClientAssertion.new(client_id: client_id, signing_key: key)
      error = assert_raises(AuthProto::PAR::ClientAssertion::Error) do
        assertion.generate_jwt(audience: audience)
      end

      _(error.cause).must_be_kind_of JWT::EncodeError
    end

    it "defaults the lifetime to 5 minutes" do
      now = Time.now.to_i
      Time.stubs(:now).returns(Time.at(now))

      jwt = client_assertion.generate_jwt(audience: audience)
      public_key = JWT::JWK.import(signing_key.to_public.to_map.to_h).public_key
      decoded, _header = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })

      _(decoded["exp"]).must_equal now + 300 # Default lifetime of 300 seconds
    end

    it "sets a unique jti for each assertion" do
      jti_values = []
      5.times do
        jwt = client_assertion.generate_jwt(audience: audience)
        public_key = JWT::JWK.import(signing_key.to_public.to_map.to_h).public_key
        decoded, = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })
        jti_values << decoded["jti"]
      end

      _(jti_values.uniq.size).must_equal 5 # All jti values must be unique
    end

    it "includes the correct kid in the header" do
      jwt = client_assertion.generate_jwt(audience: audience)
      public_key = JWT::JWK.import(signing_key.to_public.to_map.to_h).public_key
      _decoded, header = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })

      _(header["kid"]).must_equal "test-key-id"
    end
  end
end
