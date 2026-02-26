# frozen_string_literal: true

##
# Ruby Flux Starter - Backend Server
#
# Simple WebSocket proxy to Deepgram's Flux API.
# Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
#
# Key Features:
# - WebSocket proxy endpoint: WS /api/flux
# - JWT session auth via access_token.* subprotocol
# - Hardcoded flux-general-en model with configurable query parameters
# - Multi-value keyterm support
# - CORS enabled for frontend communication

require 'sinatra/base'
require 'sinatra/cross_origin'
require 'json'
require 'jwt'
require 'securerandom'
require 'toml-rb'
require 'dotenv'
require 'faye/websocket'
require 'uri'

Dotenv.load

# ============================================================================
# SECTION 1: CONFIGURATION
# ============================================================================

##
# Deepgram Flux model - hardcoded for this starter.
DEFAULT_MODEL = 'flux-general-en'

##
# Deepgram Flux WebSocket endpoint (v2!)
DEEPGRAM_STT_URL = 'wss://api.deepgram.com/v2/listen'

# ============================================================================
# SECTION 2: SESSION AUTH - JWT tokens for production security
# ============================================================================

##
# Session secret for signing JWTs.
# Auto-generated if not set via env.
SESSION_SECRET = ENV.fetch('SESSION_SECRET', SecureRandom.hex(32))

# JWT expiry time (1 hour)
JWT_EXPIRY = 3600

##
# Validates JWT from Sec-WebSocket-Protocol: access_token.<jwt> header.
# Returns the matching subprotocol string if valid, nil otherwise.
def validate_ws_token(env)
  protocol_header = env['HTTP_SEC_WEBSOCKET_PROTOCOL'] || ''
  protocols = protocol_header.split(',').map(&:strip)
  token_proto = protocols.find { |p| p.start_with?('access_token.') }
  return nil unless token_proto

  token = token_proto.sub('access_token.', '')
  begin
    JWT.decode(token, SESSION_SECRET, true, algorithm: 'HS256')
    token_proto
  rescue JWT::ExpiredSignature, JWT::DecodeError
    nil
  end
end

# ============================================================================
# SECTION 3: API KEY LOADING
# ============================================================================

##
# Loads the Deepgram API key from environment variables.
# Exits with a helpful error message if not found.
def load_api_key
  api_key = ENV['DEEPGRAM_API_KEY']

  if api_key.nil? || api_key.empty?
    warn "\n  ERROR: Deepgram API key not found!\n"
    warn "Please set your API key using one of these methods:\n"
    warn "1. Create a .env file (recommended):"
    warn "   DEEPGRAM_API_KEY=your_api_key_here\n"
    warn "2. Environment variable:"
    warn "   export DEEPGRAM_API_KEY=your_api_key_here\n"
    warn "Get your API key at: https://console.deepgram.com\n"
    exit 1
  end

  api_key
end

API_KEY = load_api_key

# ============================================================================
# SECTION 4: WEBSOCKET MIDDLEWARE
# ============================================================================

##
# Rack middleware that intercepts WebSocket upgrade requests on /api/flux
# and proxies them bidirectionally to Deepgram's Flux API.
#
# Uses faye-websocket for the client side and faye-websocket Client for
# the upstream Deepgram connection. Runs on EventMachine via Puma's
# Rack hijack support.
class WebSocketMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    # Only intercept WebSocket upgrades on /api/flux
    if Faye::WebSocket.websocket?(env) && env['PATH_INFO'] == '/api/flux'
      handle_flux_websocket(env)
    else
      @app.call(env)
    end
  end

  private

  ##
  # Handles a WebSocket upgrade on /api/flux.
  # Validates JWT, parses query params, opens upstream Deepgram connection,
  # and wires bidirectional message forwarding.
  def handle_flux_websocket(env)
    # Validate JWT from subprotocol
    valid_proto = validate_ws_token(env)
    unless valid_proto
      puts 'WebSocket auth failed: invalid or missing token'
      return [401, { 'Content-Type' => 'text/plain' }, ['Unauthorized']]
    end

    # Accept client WebSocket, echoing back the access_token.* subprotocol
    client_ws = Faye::WebSocket.new(env, [valid_proto])

    puts 'Client connected to /api/flux'

    # Parse query parameters from the request URL
    query = Rack::Utils.parse_query(env['QUERY_STRING'] || '')

    model = DEFAULT_MODEL
    encoding = query['encoding'] || 'linear16'
    sample_rate = query['sample_rate'] || '16000'
    eot_threshold = query['eot_threshold']
    eager_eot_threshold = query['eager_eot_threshold']
    eot_timeout_ms = query['eot_timeout_ms']
    # Multi-value keyterm support: Rack parses keyterm[] or repeated keyterm
    keyterms = Array(query['keyterm'])

    puts "Flux Config - model: #{model}, encoding: #{encoding}, sample_rate: #{sample_rate}"

    # Build Deepgram WebSocket URL with query parameters
    deepgram_params = {
      'model' => model,
      'encoding' => encoding,
      'sample_rate' => sample_rate
    }
    deepgram_params['eot_threshold'] = eot_threshold if eot_threshold
    deepgram_params['eager_eot_threshold'] = eager_eot_threshold if eager_eot_threshold
    deepgram_params['eot_timeout_ms'] = eot_timeout_ms if eot_timeout_ms

    deepgram_url = "#{DEEPGRAM_STT_URL}?#{URI.encode_www_form(deepgram_params)}"
    # Append multi-value keyterm params
    keyterms.each do |term|
      deepgram_url += "&keyterm=#{URI.encode_www_form_component(term)}"
    end

    puts "Deepgram URL: #{deepgram_url}"

    # Message counters for logging
    client_message_count = 0
    deepgram_message_count = 0

    # Open upstream WebSocket connection to Deepgram
    deepgram_ws = Faye::WebSocket::Client.new(
      deepgram_url,
      nil,
      headers: { 'Authorization' => "Token #{API_KEY}" }
    )

    # --- Deepgram -> Client forwarding ---

    deepgram_ws.on :open do |_event|
      puts 'Connected to Deepgram Flux API'
    end

    deepgram_ws.on :message do |event|
      deepgram_message_count += 1
      if (deepgram_message_count % 10).zero? || event.data.is_a?(String)
        puts "<- Deepgram message ##{deepgram_message_count}"
      end

      # Forward to client (preserve binary vs text framing)
      if event.data.is_a?(Array)
        client_ws.send(event.data) if client_ws
      else
        client_ws.send(event.data) if client_ws
      end
    end

    deepgram_ws.on :error do |event|
      puts "Deepgram WebSocket error: #{event.message}"
      client_ws&.close(1011, 'Deepgram connection error')
    end

    deepgram_ws.on :close do |event|
      puts "Deepgram connection closed: #{event.code} #{event.reason}"
      client_ws&.close(event.code, event.reason)
      deepgram_ws = nil
    end

    # --- Client -> Deepgram forwarding ---

    client_ws.on :message do |event|
      client_message_count += 1
      if (client_message_count % 100).zero?
        puts "-> Client message ##{client_message_count}"
      end

      # Forward binary audio or JSON text to Deepgram
      deepgram_ws&.send(event.data)
    end

    client_ws.on :close do |event|
      puts "Client disconnected: #{event.code} #{event.reason}"
      deepgram_ws&.close(1000, 'Client disconnected')
      deepgram_ws = nil
      client_ws = nil
    end

    client_ws.on :error do |event|
      puts "Client WebSocket error: #{event.message}"
      deepgram_ws&.close(1011, 'Client error')
    end

    # Return async Rack response (WebSocket hijacks the connection)
    client_ws.rack_response
  end
end

# ============================================================================
# SECTION 5: SINATRA APPLICATION
# ============================================================================

##
# Main Sinatra application class.
# Handles HTTP routes: session, metadata, health.
class App < Sinatra::Base
  register Sinatra::CrossOrigin

  configure do
    enable :cross_origin
    set :port, ENV.fetch('PORT', 8081).to_i
    set :bind, ENV.fetch('HOST', '0.0.0.0')
  end

  before do
    response.headers['Access-Control-Allow-Origin'] = '*'
  end

  options '*' do
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    200
  end

  # ==========================================================================
  # SESSION ROUTES - Auth endpoints (unprotected)
  # ==========================================================================

  ##
  # GET /api/session - Issues a signed JWT for session authentication.
  get '/api/session' do
    content_type :json

    now = Time.now.to_i
    payload = {
      iat: now,
      exp: now + JWT_EXPIRY
    }

    token = JWT.encode(payload, SESSION_SECRET, 'HS256')
    JSON.generate(token: token)
  end

  # ==========================================================================
  # METADATA ROUTE
  # ==========================================================================

  ##
  # GET /api/metadata
  #
  # Returns metadata about this starter application from deepgram.toml.
  # Required for standardization compliance.
  get '/api/metadata' do
    content_type :json

    begin
      toml_path = File.join(File.dirname(__FILE__), 'deepgram.toml')
      config = TomlRB.load_file(toml_path)

      unless config['meta']
        status 500
        return JSON.generate(
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Missing [meta] section in deepgram.toml'
        )
      end

      JSON.generate(config['meta'])
    rescue StandardError => e
      logger.error "Error reading metadata: #{e.message}"
      status 500
      JSON.generate(
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Failed to read metadata from deepgram.toml'
      )
    end
  end

  # ==========================================================================
  # HEALTH CHECK
  # ==========================================================================

  ##
  # GET /health - Simple health-check endpoint.
  get '/health' do
    content_type :json
    JSON.generate(status: 'ok')
  end
end

# ============================================================================
# SECTION 6: SERVER START
# ============================================================================

# Print startup banner when run directly
if __FILE__ == $PROGRAM_NAME
  puts ''
  puts '=' * 70
  puts "  Ruby Flux Server (Backend API)"
  puts '=' * 70
  puts "  Server:   http://localhost:#{ENV.fetch('PORT', 8081)}"
  puts ''
  puts '  GET  /api/session'
  puts '  WS   /api/flux (auth required)'
  puts '  GET  /api/metadata'
  puts '  GET  /health'
  puts '=' * 70
  puts ''
end
