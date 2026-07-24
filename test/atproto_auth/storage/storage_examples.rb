# frozen_string_literal: true

module AtprotoAuth
  module Test
    # Shared examples for testing storage implementations
    # Include this module in storage implementation tests
    module StorageExamples
      def self.included(base)
        base.class_eval do
          describe "basic operations" do
            it "stores and retrieves values" do
              storage.set("atproto:test:key", "value")
              assert_equal "value", storage.get("atproto:test:key")
            end

            it "handles nil values" do
              storage.set("atproto:test:nil", nil)
              assert_nil storage.get("atproto:test:nil")
            end

            it "returns nil for missing keys" do
              assert_nil storage.get("atproto:test:missing")
            end

            it "deletes values" do
              storage.set("atproto:test:delete", "value")
              assert storage.delete("atproto:test:delete")
              assert_nil storage.get("atproto:test:delete")
            end

            it "checks existence" do
              storage.set("atproto:test:exists", "value")
              assert storage.exists?("atproto:test:exists")
              refute storage.exists?("atproto:test:missing")
            end
          end

          describe "key validation" do
            it "requires atproto: prefix" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set("invalid:key", "value")
              end
            end

            it "rejects nil keys" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set(nil, "value")
              end
            end

            it "rejects empty keys" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set("", "value")
              end
            end

            it "rejects non-string keys" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set(123, "value")
              end
            end
          end

          describe "TTL handling" do
            it "expires values after TTL" do
              storage.set("atproto:test:ttl", "value", ttl: 1)
              assert_equal "value", storage.get("atproto:test:ttl")
              sleep 1.1 # Wait for expiration
              assert_nil storage.get("atproto:test:ttl")
            end

            it "validates TTL values" do
              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set("atproto:test:ttl", "value", ttl: -1)
              end

              assert_raises(AtprotoAuth::Storage::StorageError) do
                storage.set("atproto:test:ttl", "value", ttl: "invalid")
              end
            end

            it "handles nil TTL" do
              storage.set("atproto:test:ttl", "value", ttl: nil)
              assert_equal "value", storage.get("atproto:test:ttl")
            end
          end

          describe "locking" do
            it "executes blocks with locks" do
              result = storage.with_lock("atproto:test:lock", ttl: 30) do
                "success"
              end

              assert_equal "success", result
              assert storage.with_lock("atproto:test:lock", ttl: 30) { true }
            end

            it "expires locks after TTL" do
              storage.with_lock("atproto:test:lock", ttl: 1) do
                assert_raises(AtprotoAuth::Storage::LockError) do
                  storage.with_lock("atproto:test:lock", ttl: 30) { true }
                end

                sleep 1.1 # Wait for expiration
                assert storage.with_lock("atproto:test:lock", ttl: 30) { true }
              end
            end

            it "releases locks after block even if error raised" do
              assert_raises(RuntimeError) do
                storage.with_lock("atproto:test:lock", ttl: 30) do
                  raise "test error"
                end
              end

              assert storage.with_lock("atproto:test:lock", ttl: 30) { true }
            end

            it "requires block for with_lock" do
              assert_raises(ArgumentError) do
                storage.with_lock("atproto:test:lock", ttl: 30)
              end
            end
          end

          describe "concurrency" do
            it "handles concurrent access to same key" do
              threads = 10.times.map do
                Thread.new do
                  storage.set("atproto:test:concurrent", "value")
                  storage.get("atproto:test:concurrent")
                  storage.delete("atproto:test:concurrent")
                end
              end

              threads.each(&:join)
              assert_nil storage.get("atproto:test:concurrent")
            end

            it "handles concurrent lock acquisition" do
              success_count = 0
              fail_count = 0

              threads = 10.times.map do
                Thread.new do
                  begin
                    storage.with_lock("atproto:test:lock", ttl: 30) do
                      success_count += 1
                      sleep 0.1
                    end
                  rescue AtprotoAuth::Storage::LockError
                    fail_count += 1
                  end
                end
              end

              threads.each(&:join)
              assert_equal 1, success_count
              assert_equal 9, fail_count
            end
          end
        end
      end
    end
  end
end
