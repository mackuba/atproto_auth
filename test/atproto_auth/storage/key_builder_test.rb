# frozen_string_literal: true

require_relative "../../test_helper"

describe AuthProto::Storage::KeyBuilder do
  describe ".session_key" do
    it "builds valid session key" do
      assert_equal "atproto:session:123", AuthProto::Storage::KeyBuilder.session_key("123")
    end
  end

  describe ".state_key" do
    it "builds valid state key" do
      assert_equal "atproto:state:xyz789", AuthProto::Storage::KeyBuilder.state_key("xyz789")
    end
  end

  describe ".nonce_key" do
    it "builds valid nonce key" do
      assert_equal "atproto:nonce:example.com", AuthProto::Storage::KeyBuilder.nonce_key("example.com")
    end
  end

  describe ".dpop_key" do
    it "builds valid dpop key" do
      assert_equal "atproto:dpop:client123", AuthProto::Storage::KeyBuilder.dpop_key("client123")
    end
  end

  describe ".lock_key" do
    it "builds valid lock key" do
      assert_equal "atproto:lock:session:123",
                   AuthProto::Storage::KeyBuilder.lock_key("session", "123")
    end
  end
end
