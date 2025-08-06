#!/bin/bash

# OpenAI-compatible MCP Server for Code Search
# This script starts an MCP server that can be used with ChatGPT

# Default configuration
DEFAULT_CODE_DIR="/Users/matt/SynologyDrive/code/projectflow"
DEFAULT_PORT=8888
DEFAULT_HOST="0.0.0.0"
DEFAULT_SSL_CERT="/Users/matt/fsdownload/cert.pem"
DEFAULT_SSL_KEY="/Users/matt/fsdownload/key.pem"
USE_UV=false

# Check if uv is available
if command -v uv &> /dev/null; then
    USE_UV=true
fi

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
        --use-uv)
            USE_UV=true
            shift
            ;;
        --no-uv)
            USE_UV=false
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --code-dir DIR     Directory to search for code files (default: current directory)"
            echo "  --port PORT        Port to run server on (default: 8000)"
            echo "  --host HOST        Host to bind to (default: 0.0.0.0)"
            echo "  --ssl-cert FILE    SSL certificate file for HTTPS"
            echo "  --ssl-key FILE     SSL private key file for HTTPS"
            echo "  --use-uv           Force use of uv command (auto-detected if available)"
            echo "  --no-uv            Don't use uv even if available"
            echo "  --help             Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  MCP_CODE_DIR       Directory to search (overridden by --code-dir)"
            echo "  MCP_IGNORE_DIRS    Comma-separated list of directories to ignore"
            echo "  MCP_SERVER_NAME    Server name for identification"
            echo ""
            echo "Examples:"
            echo "  # HTTP server for current directory"
            echo "  $0"
            echo ""
            echo "  # HTTPS server for specific directory"
            echo "  $0 --code-dir /path/to/code --ssl-cert cert.pem --ssl-key key.pem"
            echo ""
            echo "  # Using uv with HTTPS"
            echo "  $0 --use-uv --code-dir /path/to/code --ssl-cert cert.pem --ssl-key key.pem"
            echo ""
            echo "  # With custom ignore directories"
            echo "  MCP_IGNORE_DIRS='.git,node_modules,dist' $0 --code-dir /path/to/project"
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

# Determine protocol
if [[ -n "$SSL_CERT" && -n "$SSL_KEY" ]]; then
    PROTOCOL="https"
    SERVER_BASE_URL="https://${HOST}:${PORT}"
else
    PROTOCOL="http"
    SERVER_BASE_URL="http://${HOST}:${PORT}"
fi

echo "========================================="
echo "OpenAI-compatible MCP Code Search Server"
echo "========================================="
echo ""
echo "Configuration:"
echo "  Code directory: $CODE_DIR"
echo "  Server URL: ${PROTOCOL}://${HOST}:${PORT}"
echo "  SSE endpoint: ${SERVER_BASE_URL}/sse/"
if [ "$USE_UV" = true ]; then
    echo "  Using: uv run"
else
    echo "  Using: python -m"
fi
echo ""

if [[ -n "$SSL_CERT" && -n "$SSL_KEY" ]]; then
    echo "  SSL Certificate: $SSL_CERT"
    echo "  SSL Key: $SSL_KEY"
    echo ""
fi

echo "To connect from ChatGPT:"
echo "  1. Go to ChatGPT Settings > Connectors"
echo "  2. Add a new MCP server"
echo "  3. Use this URL: ${SERVER_BASE_URL}/sse/"
echo ""
echo "Starting server..."
echo "========================================="
echo ""

# Build the command
if [ "$USE_UV" = true ]; then
    # Use uv run with codemcp serve --openai-mode
    CMD="uv run codemcp serve --openai-mode"
    CMD="$CMD --host $HOST --port $PORT"
    
    if [[ -n "$CODE_DIR" ]]; then
        CMD="$CMD --code-dir $CODE_DIR"
    fi
    
    if [[ -n "$SSL_CERT" && -n "$SSL_KEY" ]]; then
        CMD="$CMD --ssl-cert $SSL_CERT --ssl-key $SSL_KEY"
    fi
else
    # Use python -m with environment variables
    export MCP_CODE_DIR="$CODE_DIR"
    export MCP_SERVER_BASE_URL="${SERVER_BASE_URL}"
    
    if [[ -n "$SSL_CERT" && -n "$SSL_KEY" ]]; then
        export MCP_SSL_CERT="$SSL_CERT"
        export MCP_SSL_KEY="$SSL_KEY"
    fi
    
    CMD="python -m codemcp.openai_mcp_server"
fi

# Run the server
echo "Executing: $CMD"
$CMD
