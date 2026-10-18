# frozen_string_literal: true

module AuthProto
  module Identity

    #
    # Validates decentralized identifiers (DIDs)
    #

    class DID

      # DID method prefixes accepted by the prefix validator.
      # @return [Array<String>]
      PREFIXES = ["did:plc:", "did:web:"].freeze

      # Wraps a DID string without validating it.
      # @param did [String] DID to check with {#validate!}
      #
      def initialize(did)
        @did = did
      end

      # Checks that the identifier begins with a supported DID method prefix.
      #
      # This is a prefix check; it does not validate method-specific syntax or reject
      # `did:web` path components.
      #
      # @return [void]
      # @raise [Identity::Error] if the prefix is not `did:plc:` or `did:web:`
      #
      def validate!
        return if PREFIXES.any? { |prefix| @did.start_with?(prefix) }

        raise Error, "Invalid DID format (must be one of #{PREFIXES.join(", ")}): #{@did}"
      end

      # Returns the original DID string.
      # @return [String] wrapped identifier
      def to_s
        @did
      end
    end
  end
end
