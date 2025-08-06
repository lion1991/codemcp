#!/bin/bash

# OpenAI-compatible MCP Server with OAuth Authentication
# This script starts an MCP server with OAuth 2.0 support for ChatGPT

# Load environment variables from .env file if it exists
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
elif [ -f "oauth_config.env" ]; then
    export $(cat oauth_config.env | grep -v '^#' | xargs)
fi

# Default configuration (can be overridden by environment variables)
DEFAULT_CODE_DIR="${MCP_CODE_DIR:-/Users/matt/SynologyDrive/code/projectflow}"
DEFAULT_PORT=8888
DEFAULT_HOST="0.0.0.0"
DEFAULT_SSL_CERT="${MCP_SSL_CERT:-/Users/matt/fsdownload/cert.pem}"
DEFAULT_SSL_KEY="${MCP_SSL_KEY:-/Users/matt/fsdownload/key.pem}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --code-dir)
            CODE_DIR="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --host)
            HOST="$2"
            shift 2
            ;;
        --ssl-cert)
            SSL_CERT="$2"
            shift 2
            ;;
        --ssl-key)
            SSL_KEY="$2"
            shift 2
            ;;
        --client-id)
            export MCP_OAUTH_CLIENT_ID="$2"
            shift 2
            ;;
        --client-secret)
            export MCP_OAUTH_CLIENT_SECRET="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --code-dir DIR        Directory to search for code files"
            echo "  --port PORT           Port to run server on (default: 8443)"
            echo "  --host HOST           Host to bind to (default: 0.0.0.0)"
            echo "  --ssl-cert FILE       SSL certificate file for HTTPS"
            echo "  --ssl-key FILE        SSL private key file for HTTPS"
            echo "  --client-id ID        OAuth client ID"
            echo "  --client-secret SEC   OAuth client secret"
            echo "  --help                Show this help message"
            echo ""
            echo "Environment variables (via .env file):"
            echo "  MCP_CODE_DIR          Directory to search"
            echo "  MCP_SERVER_BASE_URL   Base URL for the server"
            echo "  MCP_OAUTH_CLIENT_ID   OAuth client ID"
            echo "  MCP_OAUTH_CLIENT_SECRET OAuth client secret"
            echo "  MCP_SSL_CERT          SSL certificate path"
            echo "  MCP_SSL_KEY           SSL key path"
            echo ""
            echo "OAuth Setup for ChatGPT:"
            echo "  1. Start this server with your domain"
            echo "  2. In ChatGPT, add connector with:"
            echo "     - Server URL: https://your-domain:8443/sse/"
            echo "     - Auth Type: OAuth 2.0"
            echo "     - Auth URL: https://your-domain:8443/oauth/authorize"
            echo "     - Token URL: https://your-domain:8443/oauth/token"
            echo "     - Scope: read"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Set defaults if not provided
CODE_DIR="${CODE_DIR:-$DEFAULT_CODE_DIR}"
PORT="${PORT:-$DEFAULT_PORT}"
HOST="${HOST:-$DEFAULT_HOST}"
SSL_CERT="${SSL_CERT:-$DEFAULT_SSL_CERT}"
SSL_KEY="${SSL_KEY:-$DEFAULT_SSL_KEY}"

# Export environment variables
export MCP_CODE_DIR="$CODE_DIR"
export MCP_SSL_CERT="$SSL_CERT"
export MCP_SSL_KEY="$SSL_KEY"

# Set server base URL if not already set
if [ -z "$MCP_SERVER_BASE_URL" ]; then
    export MCP_SERVER_BASE_URL="https://${HOST}:${PORT}"
fi

# Generate client secret if not set
if [ -z "$MCP_OAUTH_CLIENT_SECRET" ]; then
    export MCP_OAUTH_CLIENT_SECRET=$(openssl rand -hex 32)
    echo "Generated OAuth Client Secret: $MCP_OAUTH_CLIENT_SECRET"
    echo "(Save this for future use)"
fi

echo "========================================="
echo "MCP Code Search Server with OAuth"
echo "========================================="
echo ""
echo "Configuration:"
echo "  Code directory: $CODE_DIR"
echo "  Server URL: $MCP_SERVER_BASE_URL"
echo "  SSL Certificate: $SSL_CERT"
echo "  SSL Key: $SSL_KEY"
echo ""
echo "OAuth Configuration:"
echo "  Client ID: ${MCP_OAUTH_CLIENT_ID:-mcp-code-search}"
echo "  Authorization URL: ${MCP_SERVER_BASE_URL}/oauth/authorize"
echo "  Token URL: ${MCP_SERVER_BASE_URL}/oauth/token"
echo "  JWKS URL: ${MCP_SERVER_BASE_URL}/.well-known/jwks.json"
echo ""
echo "ChatGPT Connector Setup:"
echo "  1. Go to ChatGPT Settings > Connectors"
echo "  2. Add new MCP server"
echo "  3. Configuration:"
echo "     - Server URL: ${MCP_SERVER_BASE_URL}/sse/"
echo "     - Authentication: OAuth 2.0"
echo "     - Client ID: ${MCP_OAUTH_CLIENT_ID:-mcp-code-search}"
echo "     - Authorization URL: ${MCP_SERVER_BASE_URL}/oauth/authorize"
echo "     - Token URL: ${MCP_SERVER_BASE_URL}/oauth/token"
echo "     - Scope: read"
echo ""
echo "Starting server..."
echo "========================================="
echo ""

# Run the OAuth-enabled server
python -m codemcp.openai_mcp_oauth_server