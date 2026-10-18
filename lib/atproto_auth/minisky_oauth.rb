# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

require 'atproto_auth'
require 'minisky'

# Experimental Minisky client backed by an AuthProto session.
# Requiring atproto_auth alone does not load Minisky or this integration.
class MiniskyOAuth
  include Minisky::Requests

  MAX_NONCE_RETRIES = 2

  attr_reader :host, :oauth_client, :session_id

  def initialize(host, client_id:, redirect_uri:, metadata: nil, dpop_key: nil)
    @host = host
    @session_id = nil

    @send_auth_headers = true
    @auto_manage_tokens = false

    @oauth_client = AuthProto::Client.new(
      client_id: client_id,
      redirect_uri: redirect_uri,
      metadata: metadata,
      dpop_key: dpop_key
    )
  end

  # Minisky's config normally holds app-password credentials. OAuth owns them here.
  def config
    nil
  end

  def authorize(**options)
    oauth_client.authorize(**options).tap { |result| @session_id = result.fetch(:session_id) }
  end

  def handle_callback(**options)
    oauth_client.handle_callback(**options).tap { |result| @session_id = result.fetch(:session_id) }
  end

  def get_request(method, params = nil, auth: default_auth_mode, headers: nil)
    return super unless auth

    raise ArgumentError, "OAuth requests accept auth: true or false, not a bearer token" unless auth == true

    url = build_request_uri(method).dup
    url.query = URI.encode_www_form(params) if params && !params.empty?

    response = oauth_request(Net::HTTP::Get, url, headers || {})
    handle_response(response)
  end

  def post_request(method, data = nil, auth: default_auth_mode, headers: nil, params: nil)
    return super unless auth

    raise ArgumentError, "OAuth requests accept auth: true or false, not a bearer token" unless auth == true

    url = build_request_uri(method).dup
    url.query = URI.encode_www_form(params) if params && !params.empty?
    headers = (headers || {}).dup

    body = if data.is_a?(String) || data.nil?
             data.to_s
           else
             unless headers.keys.any? { |key| key.to_s.downcase == "content-type" }
               headers["Content-Type"] = "application/json"
             end
             data.to_json
           end

    response = oauth_request(Net::HTTP::Post, url, headers, body: body)
    handle_response(response)
  end

  def log_in(*)
    raise NotImplementedError, "Use authorize and handle_callback for OAuth login"
  end

  def perform_token_refresh
    oauth_client.refresh_token(session_id)
  end

  def check_access
    session = oauth_client.session_manager.get_session(session_id) if session_id
    raise Minisky::AuthError, "Complete OAuth login before making authenticated requests" unless session&.tokens

    return :ok unless session.tokens.expired?

    raise Minisky::AuthError, "OAuth session cannot be refreshed; log in again" unless session.renewable?

    perform_token_refresh
    :refreshed
  end

  private

  def oauth_request(request_class, url, headers, body: nil)
    check_access

    nonce_retries = 0
    refreshed = false

    proof_url = url.dup
    proof_url.query = nil
    proof_url.fragment = nil

    loop do
      # Fresh proof for every attempt; callers cannot override OAuth auth headers.
      request_headers = headers.reject { |key, _| %w[authorization dpop].include?(key.to_s.downcase) }
      request_headers.merge!(oauth_client.auth_headers(
                               session_id: session_id, method: request_class::METHOD, url: proof_url.to_s
                             ))

      request = request_class.new(url, request_headers)
      request.body = body unless body.nil?
      response = make_request(request)

      nonce = response["DPoP-Nonce"]
      oauth_client.dpop_client.process_response(response.each_header.to_h, url.to_s) if nonce && !nonce.empty?
      error = authentication_error(response)

      if response.code.to_i == 401 && error == "use_dpop_nonce"
        unless nonce && !nonce.empty?
          raise AuthProto::DPoP::Client::Error, "DPoP nonce challenge (HTTP 401) is missing DPoP-Nonce"
        end
        return response if nonce_retries >= MAX_NONCE_RETRIES

        nonce_retries += 1
      elsif response.code.to_i == 401 && error == "invalid_token" && !refreshed
        perform_token_refresh
        refreshed = true
      else
        return response
      end
    end
  end

  def authentication_error(response)
    # Only interpret a single DPoP challenge. Leave other auth schemes and
    # ambiguous multi-challenge headers to Minisky's normal error handling.
    challenge = response["WWW-Authenticate"].to_s
    return unless challenge.match?(/\ADPoP\s/i)
    return if challenge.match?(/,\s*(?:Bearer|Basic|DPoP)\b/i)

    challenge[/\berror\s*=\s*"(use_dpop_nonce|invalid_token)"/i, 1]
  end
end
