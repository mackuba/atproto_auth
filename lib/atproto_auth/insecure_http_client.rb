# frozen_string_literal: true

require_relative "http_client"

module AtprotoAuth
  # Development transport for mixed local HTTP and remote HTTPS requests.
  # Allows private/loopback destinations; HTTPS certificate verification is kept.
  class InsecureHttpClient < HttpClient
    ALLOWED_SCHEMES = %w[http https].freeze

    private

    def validate_ip!(_uri)
      # Deliberately bypass IP restrictions for local development environments.
    end
  end
end
