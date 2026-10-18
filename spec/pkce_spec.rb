# frozen_string_literal: true

describe AuthProto::PKCE do
  let(:valid_verifier) { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~" }
  let(:short_verifier) { "short" }
  let(:long_verifier) { "a" * 129 }
  let(:invalid_verifier) { "invalid_verifier!" }
  let(:challenge) { AuthProto::PKCE.generate_challenge(valid_verifier) }

  describe ".generate_verifier" do
    it "should generate a valid code verifier of default length" do
      verifier = AuthProto::PKCE.generate_verifier
      verifier.length.should == AuthProto::PKCE::MAX_VERIFIER_LENGTH
      verifier.should match(AuthProto::PKCE::ALLOWED_VERIFIER_CHARS)
    end

    it "should generate a valid code verifier of specified length" do
      length = 50
      verifier = AuthProto::PKCE.generate_verifier(length)
      verifier.length.should == length
      verifier.should match(AuthProto::PKCE::ALLOWED_VERIFIER_CHARS)
    end

    it "should raise an error for a length below the minimum" do
      expect {
        AuthProto::PKCE.generate_verifier(AuthProto::PKCE::MIN_VERIFIER_LENGTH - 1)
      }.to raise_error(AuthProto::PKCE::Error)
    end

    it "should raise an error for a length above the maximum" do
      expect {
        AuthProto::PKCE.generate_verifier(AuthProto::PKCE::MAX_VERIFIER_LENGTH + 1)
      }.to raise_error(AuthProto::PKCE::Error)
    end
  end

  describe ".generate_challenge" do
    it "should generate a valid challenge for a given verifier" do
      challenge = AuthProto::PKCE.generate_challenge(valid_verifier)
      challenge.should match(/^[A-Za-z0-9\-_]+$/)
    end

    it "should raise an error for a nil verifier" do
      expect {
        AuthProto::PKCE.generate_challenge(nil)
      }.to raise_error(AuthProto::PKCE::Error)
    end

    it "should raise an error for an empty verifier" do
      expect {
        AuthProto::PKCE.generate_challenge("")
      }.to raise_error(AuthProto::PKCE::Error)
    end

    it "should raise an error for a verifier below the minimum length" do
      expect {
        AuthProto::PKCE.generate_challenge(short_verifier)
      }.to raise_error(AuthProto::PKCE::Error)
    end

    it "should raise an error for a verifier above the maximum length" do
      expect {
        AuthProto::PKCE.generate_challenge(long_verifier)
      }.to raise_error(AuthProto::PKCE::Error)
    end

    it "should raise an error for a verifier with invalid characters" do
      expect {
        AuthProto::PKCE.generate_challenge(invalid_verifier)
      }.to raise_error(AuthProto::PKCE::Error)
    end
  end

  describe ".verify" do
    it "should return true for a valid verifier and matching challenge" do
      result = AuthProto::PKCE.verify(challenge, valid_verifier)
      result.should be true
    end

    it "should return false for a valid verifier and non-matching challenge" do
      non_matching_challenge = AuthProto::PKCE.generate_challenge("different_verifier_different_verifier_12345")
      result = AuthProto::PKCE.verify(non_matching_challenge, valid_verifier)
      result.should be false
    end

    it "should raise an error for a nil challenge" do
      expect {
        AuthProto::PKCE.verify(nil, valid_verifier)
      }.to raise_error(AuthProto::PKCE::Error)
    end

    it "should raise an error for a nil verifier" do
      expect {
        AuthProto::PKCE.verify(challenge, nil)
      }.to raise_error(AuthProto::PKCE::Error)
    end

    it "should raise an error for a verifier with invalid characters" do
      expect {
        AuthProto::PKCE.verify(challenge, invalid_verifier)
      }.to raise_error(AuthProto::PKCE::Error)
    end
  end
end
