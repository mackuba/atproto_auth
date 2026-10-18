# frozen_string_literal: true

require_relative 'storage_examples'

describe AuthProto::Storage::Memory do
  let(:storage) { AuthProto::Storage::Memory.new }

  include_examples "a storage implementation"

  describe "memory-specific behavior" do
    it "should clean up expired keys automatically" do
      storage.set("atproto:test:short", "value", ttl: 1)
      storage.set("atproto:test:long", "value", ttl: 3600)

      storage.get("atproto:test:short").should == "value"
      sleep 1.1 # Wait for expiration
      storage.get("atproto:test:short").should be_nil
      storage.get("atproto:test:long").should == "value"
    end

    it "should handle clear operation" do
      storage.set("atproto:test:1", "value1")
      storage.set("atproto:test:2", "value2")

      storage.clear

      storage.get("atproto:test:1").should be_nil
      storage.get("atproto:test:2").should be_nil
    end
  end
end
