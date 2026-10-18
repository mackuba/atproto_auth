# frozen_string_literal: true

module AuthProto
  module Identity

    #
    # Represents and validates a DID Document in the AT Protocol.
    #
    # DID Documents contain critical service information about user accounts, including:
    # - The Personal Data Server (PDS) hosting the account
    # - Associated handles for the account
    # - Key material for identity verification
    # - Service endpoints for various protocols
    #
    # Accepts either a top-level `pds` field or a PDS service entry, providing a
    # consistent interface for accessing and validating document data.
    #
    # @example With a top-level PDS endpoint
    #   data = {
    #     "id" => "did:plc:abc123",
    #     "alsoKnownAs" => ["at://alice.example.com"],
    #     "pds" => "https://pds.example.com"
    #   }
    #   doc = AuthProto::Identity::Document.new(data)
    #
    #   puts doc.pds                    # => "https://pds.example.com"
    #   puts doc.has_handle?("alice.example.com")  # => true
    #
    # @example With a PDS service entry
    #   service_data = {
    #     "id" => "did:plc:abc123",
    #     "service" => [{
    #       "id" => "#atproto_pds",
    #       "type" => "AtprotoPersonalDataServer",
    #       "serviceEndpoint" => "https://pds.example.com"
    #     }]
    #   }
    #   doc = AuthProto::Identity::Document.new(service_data)
    #   puts doc.pds  # => "https://pds.example.com"
    #

    class Document

      # DID from the document `id` field.
      # @return [String]
      attr_reader :did

      # `publicKeyMultibase` values extracted from verification methods.
      # @return [Array<String, nil>]
      attr_reader :rotation_keys

      # Alternative account identifiers, including `at://` handles.
      # @return [Array<String>]
      attr_reader :also_known_as

      # Service entries from the document, or an empty array.
      # @return [Array<Hash{String => Object}>]
      attr_reader :services

      # PDS endpoint from `pds` or an `AtprotoPersonalDataServer` service.
      # @return [String]
      attr_reader :pds

      # Validates a parsed DID document and extracts identity/service fields.
      #
      # Accepts a top-level `pds` endpoint or an `AtprotoPersonalDataServer` service.
      #
      # @param data [Hash{String => Object}] parsed DID document
      # @raise [DocumentError] if the document lacks an ID, valid services or a PDS endpoint
      # @raise [Identity::Error] if the DID prefix is unsupported
      #
      def initialize(data)
        validate_document!(data)

        @did = data["id"]
        @rotation_keys = data["verificationMethod"]&.map { |m| m["publicKeyMultibase"] } || []
        @also_known_as = data["alsoKnownAs"] || []
        @services = data["service"] || []
        @pds = extract_pds!(data)
      end

      # Checks if this document contains a specific handle
      #
      # @param handle [String] Handle to check (with or without @ prefix)
      # @return [Boolean] true if handle is listed in alsoKnownAs
      #
      def has_handle?(handle)
        normalized = handle.start_with?("@") ? handle[1..] : handle
        @also_known_as.any? do |aka|
          aka.start_with?("at://") && aka.delete_prefix("at://") == normalized
        end
      end

      private

      def validate_document!(data)
        raise DocumentError, "Document cannot be nil" if data.nil?
        raise DocumentError, "Document must be a Hash" unless data.is_a?(Hash)
        raise DocumentError, "Document must have id" unless data["id"]

        DID.new(data["id"]).validate!
        validate_services!(data["service"])
      end

      def validate_services!(services)
        return if services.nil?
        raise DocumentError, "services must be an array" unless services.is_a?(Array)

        services.each do |svc|
          unless svc.is_a?(Hash) && svc["id"] && svc["type"] && svc["serviceEndpoint"]
            raise DocumentError, "Invalid service entry format"
          end
        end
      end

      def extract_pds!(data)
        pds = data["pds"] # New format
        return pds if pds

        # Legacy format - look through services
        service = @services.find { |s| s["type"] == "AtprotoPersonalDataServer" }
        raise DocumentError, "No PDS location found in document" unless service

        service["serviceEndpoint"]
      end
    end
  end
end
