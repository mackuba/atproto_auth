# frozen_string_literal: true

require 'ipaddr'
require 'socket'
require 'timeout'
require 'uri'

module AuthProto

  # One-shot loopback OAuth callback listener for use from IRB.
  class LocalhostServer
    MAX_HEADER_BYTES = 16_384
    REQUEST_TIMEOUT = 5
    LOOPBACK_RANGES = [IPAddr.new("127.0.0.0/8"), IPAddr.new("::1/128")].freeze

    class CallbackError < StandardError
      attr_reader :error_code, :error_description

      def initialize(error_code, error_description)
        @error_code = error_code
        @error_description = error_description

        super([error_code, error_description].compact.join(": "))
      end
    end

    class InvalidRequest < StandardError
    end

    def self.start(metadata, timeout: 300, &block)
      new(metadata).start(timeout: timeout, &block)
    end

    def initialize(metadata)
      redirects = metadata['redirect_uris'] || metadata[:redirect_uris]

      unless redirects.is_a?(Array) && redirects.first.is_a?(String)
        raise ArgumentError, "metadata must contain a non-empty redirect_uris array"
      end

      @uri = URI(redirects.first)

      unless @uri.is_a?(URI::HTTP) && @uri.scheme == "http" && loopback_host?(@uri.hostname)
        raise ArgumentError, "The first redirect URI must be an HTTP loopback URL"
      end

      raise ArgumentError, "The redirect URI should have a valid port" unless @uri.port.between?(1, 65_535)
      raise ArgumentError, "The redirect URI should not include user info" unless !@uri.userinfo
      raise ArgumentError, "The redirect URI should not include a URL fragment" unless !@uri.fragment

      @path = (@uri.path.empty?) ? "/" : @uri.path
    rescue URI::InvalidURIError
      raise ArgumentError, "Invalid redirect URI"
    end

    def start(timeout: 300, &block)
      raise ArgumentError, "A callback block is required" unless block_given?
      raise ArgumentError, "timeout must be positive" unless timeout.is_a?(Numeric) && timeout.positive?

      server = TCPServer.new(@uri.hostname, @uri.port)

      begin
        puts "Waiting for OAuth callback at #{@uri} (Ctrl-C to cancel)"
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout

        loop do
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)

          unless remaining.positive? && IO.select([server], nil, nil, remaining)
            raise Timeout::Error, "Timed out waiting for the OAuth callback"
          end

          socket = server.accept
          success, result = handle_connection(socket, &block)

          return result if success
        end
      ensure
        server.close
      end
    end


    private

    def loopback_host?(host)
      if host&.downcase == "localhost"
        true
      elsif host
        ip = IPAddr.new(host)
        LOOPBACK_RANGES.any? { |range| range.include?(ip) }
      else
        false
      end
    rescue IPAddr::InvalidAddressError
      false
    end

    def handle_connection(socket, &block)
      params = handle_request(socket)
      return [false, nil] unless params

      begin
        if params['error']
          raise CallbackError.new(params['error'], params['error_description'])
        end

        callback_params = params.slice('code', 'state', 'iss').transform_keys(&:to_sym)
        result = yield callback_params
      rescue StandardError => e
        respond(socket, 400, "Bad Request", "Authentication failed: #{e.inspect}")
        raise
      end

      respond(socket, 200, "OK", "Authentication complete - you can close this tab.")
      [true, result]
    ensure
      socket.close
    end

    def handle_request(socket)
      method, target = read_request(socket)

      if method != 'GET'
        respond(socket, 405, "Method Not Allowed", "Use GET for the OAuth callback.")
        return
      end

      request_uri = URI(target)

      unless target.start_with?('/') && !request_uri.host && !request_uri.fragment && request_uri.path == @path
        respond(socket, 404, "Not Found", "Waiting for the OAuth callback.")
        return
      end

      extract_callback_params(request_uri)
    rescue InvalidRequest, URI::InvalidURIError, ArgumentError
      respond(socket, 400, "Bad Request", "Invalid callback request.")
      nil
    rescue Timeout::Error
      respond(socket, 408, "Request Timeout", "Request timed out.")
      nil
    rescue IOError, SystemCallError
      nil
    end

    def read_request(socket)
      Timeout.timeout(REQUEST_TIMEOUT) do
        bytes = 0
        lines = []

        loop do
          line = socket.gets("\n", MAX_HEADER_BYTES + 1)
          raise InvalidRequest unless line

          bytes += line.bytesize
          raise InvalidRequest if bytes > MAX_HEADER_BYTES
          break if line == "\r\n" || line == "\n"

          lines << line
        end

        match = /\A([A-Z]+) (\S+) HTTP\/1\.[01]\r?\n\z/.match(lines.first.to_s)
        raise InvalidRequest unless match

        [match[1], match[2]]
      end
    end

    def extract_callback_params(uri)
      pairs = URI.decode_www_form(uri.query.to_s)
      raise InvalidRequest unless pairs.map(&:first).uniq.length == pairs.length

      params = pairs.to_h

      unless params['error'] || %w[code state iss].all? { |key| params[key] && !params[key].empty? }
        raise InvalidRequest
      end

      params
    end

    def respond(socket, status, reason, body)
      socket.write("HTTP/1.1 #{status} #{reason}\r\n" +
                   "Content-Type: text/plain; charset=utf-8\r\n" +
                   "Content-Length: #{body.bytesize}\r\n" +
                   "Cache-Control: no-store\r\n" +
                   "Connection: close\r\n\r\n#{body}\n")
    rescue IOError, SystemCallError
      # A closed browser tab must not discard successful tokens or mask an error.
    end
  end
end
