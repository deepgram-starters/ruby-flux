# Ruby Flux Starter - Rack Configuration
#
# Boots Puma with WebSocket middleware and Sinatra app.
# faye-websocket requires an async-capable server (Puma with Rack hijack).

require_relative 'app'

# Load WebSocket middleware before Sinatra handles HTTP routes
use WebSocketMiddleware
run App
