# frozen_string_literal: true

require "fileutils"
require "tmpdir"

require_relative "../../test_helper"
require_relative "storage_examples"

describe AtprotoAuth::Storage::SQLite do
  let(:temporary_directory) { Dir.mktmpdir("atproto-auth-sqlite-test") }
  let(:database_path) { File.join(temporary_directory, "storage.sqlite3") }
  let(:storage) { AtprotoAuth::Storage::SQLite.new(path: database_path) }

  # Include shared storage implementation tests
  include AtprotoAuth::Test::StorageExamples

  before do
    storage
  end

  after do
    storage.close
    FileUtils.remove_entry(temporary_directory)
  end

  describe "#initialize" do
    it "creates the storage and lock tables" do
      database = SQLite3::Database.new(database_path)
      tables = database.execute(
        <<~SQL
          SELECT name
          FROM sqlite_master
          WHERE type = 'table'
        SQL
      ).flatten

      assert_includes tables, "atproto_storage"
      assert_includes tables, "atproto_locks"
    ensure
      database&.close
    end

    it "enables WAL journal mode" do
      database = SQLite3::Database.new(database_path)

      assert_equal "wal", database.get_first_value("PRAGMA journal_mode")
    ensure
      database&.close
    end

    it "configures the busy timeout" do
      custom_storage = AtprotoAuth::Storage::SQLite.new(
        path: File.join(temporary_directory, "custom.sqlite3"),
        busy_timeout: 1_234
      )
      database = custom_storage.instance_variable_get(:@database)

      assert_equal 1_234, database.get_first_value("PRAGMA busy_timeout")
    ensure
      custom_storage&.close
    end

    it "rejects invalid busy timeouts" do
      assert_raises(ArgumentError) do
        AtprotoAuth::Storage::SQLite.new(path: File.join(temporary_directory, "invalid.sqlite3"), busy_timeout: -1)
      end

      assert_raises(ArgumentError) do
        AtprotoAuth::Storage::SQLite.new(
          path: File.join(temporary_directory, "invalid.sqlite3"),
          busy_timeout: "lizard"
        )
      end
    end

    it "creates missing parent directories" do
      database_path = File.join(
        temporary_directory,
        "missing",
        "nested",
        "storage.sqlite3"
      )

      nested_storage = AtprotoAuth::Storage::SQLite.new(path: database_path)
      assert_path_exists database_path
    ensure
      nested_storage&.close
    end
  end

  describe "error handling" do
    it "wraps database initialization errors" do
      assert_raises(AtprotoAuth::Storage::SQLite::SQLiteError) do
        AtprotoAuth::Storage::SQLite.new(path: temporary_directory)
      end
    end
  end

  describe "persistence" do
    it "shares values between connections" do
      storage.set("atproto:test:persistent", "value")
      second_storage = AtprotoAuth::Storage::SQLite.new(path: database_path)

      assert_equal "value", second_storage.get("atproto:test:persistent")
    ensure
      second_storage&.close
    end
  end

  describe "TTL handling" do
    it "sets expiration time on values" do
      started_at = Time.now.to_f
      storage.set("atproto:test:ttl", "value", ttl: 2)
      finished_at = Time.now.to_f

      database = SQLite3::Database.new(database_path)
      expires_at = database.get_first_value(
        "SELECT expires_at FROM atproto_storage WHERE key = ?",
        ["atproto:test:ttl"]
      )

      assert_operator expires_at, :>=, started_at + 2
      assert_operator expires_at, :<=, finished_at + 2
    ensure
      database&.close
    end
  end

  describe "locking" do
    it "persists the lock only while the block is executing" do
      database = SQLite3::Database.new(database_path)

      storage.with_lock("atproto:test:lock", ttl: 30) do
        locks = database.get_first_value("SELECT COUNT(*) FROM atproto_locks WHERE key = ?", ["atproto:test:lock"])
        assert_equal(1, locks)
      end

      locks = database.get_first_value("SELECT COUNT(*) FROM atproto_locks WHERE key = ?", ["atproto:test:lock"])
      assert_equal(0, locks)
    ensure
      database&.close
    end

    it "ensures lock is released even if block raises error" do
      database = SQLite3::Database.new(database_path)

      assert_raises(RuntimeError) do
        storage.with_lock("atproto:test:lock", ttl: 30) do
          raise "test error"
        end
      end

      locks = database.get_first_value("SELECT COUNT(*) FROM atproto_locks WHERE key = ?", ["atproto:test:lock"])
      assert_equal(0, locks)
    ensure
      database&.close
    end

    it "coordinates locks between storage instances" do
      second_storage = AtprotoAuth::Storage::SQLite.new(path: database_path)

      storage.with_lock("atproto:test:lock", ttl: 30) do
        assert_raises(AtprotoAuth::Storage::LockError) do
          second_storage.with_lock("atproto:test:lock", ttl: 30) { true }
        end
      end
    ensure
      second_storage&.close
    end

    it "does not clean a stale lock on exit if it was already replaced" do
      second_storage = AtprotoAuth::Storage::SQLite.new(path: database_path)
      second_thread = nil

      newer_owner_acquired = Queue.new
      release_newer_owner = Queue.new

      storage.with_lock("atproto:test:lock", ttl: 1) do
        sleep 1.1

        second_thread = Thread.new do
          second_storage.with_lock("atproto:test:lock", ttl: 30) do
            newer_owner_acquired << true

            # make sure it holds the lock until the test finishes
            release_newer_owner.pop
          end
        end

        # wait until second_thread places a lock
        newer_owner_acquired.pop
      end

      # ensure that storage.with_lock exiting did not delete second_thread's lock
      assert_raises(AtprotoAuth::Storage::LockError) do
        storage.with_lock("atproto:test:lock", ttl: 30) { true }
      end
    ensure
      release_newer_owner << true if release_newer_owner
      second_thread&.join
      second_storage&.close
    end
  end
end
