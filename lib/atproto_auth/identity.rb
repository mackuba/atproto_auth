# frozen_string_literal: true

module AuthProto

  #
  # Handles identity resolution, verification and management for AT Protocol OAuth.
  # This module provides functionality to resolve handles to DIDs, verify identity
  # documents, validate PDS locations, and verify authorization server bindings.
  #
  # The module consists of three main components:
  #
  # 1. {Document} - Represents and validates AT Protocol DID documents,
  #    handling extraction of crucial service endpoints and verification.
  #
  # 2. {Resolver} - Handles resolution of handles to DIDs and fetching of
  #    DID documents, with support for both DNS and HTTP-based resolution.
  #
  # 3. {Error} classes - Structured error hierarchy for handling different
  #    types of identity-related failures.
  #

  module Identity

    # Base class for identity validation and resolution failures.
    class Error < Error; end

    # Raised when a handle, DID document or PDS location cannot be resolved.
    class ResolutionError < Error; end

    # Raised when handle, PDS or issuer bindings cannot be verified.
    class ValidationError < Error; end

    # Raised when a DID document lacks required identity or service information.
    class DocumentError < Error; end
  end
end
