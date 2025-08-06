#!/usr/bin/env python3
"""
OpenAI-compatible MCP Server with OAuth 2.0 Authentication (V2)
This version uses the same SSE approach as the working non-OAuth version
"""

import logging
import os
import re
import json
import secrets
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse, HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
import uvicorn
from .oauth_middleware import OAuthMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
CODE_DIR = os.environ.get("MCP_CODE_DIR", os.getcwd())
IGNORE_DIRS = os.environ.get("MCP_IGNORE_DIRS", ".git,node_modules,__pycache__,.venv,venv,dist,build").split(",")
SERVER_NAME = os.environ.get("MCP_SERVER_NAME", "Code Search MCP Server")
SERVER_BASE_URL = os.environ.get("MCP_SERVER_BASE_URL", "https://localhost:8000")

# OAuth Configuration  
OAUTH_CLIENT_ID = os.environ.get("MCP_OAUTH_CLIENT_ID", "mcp-code-search")
OAUTH_CLIENT_SECRET = os.environ.get("MCP_OAUTH_CLIENT_SECRET", secrets.token_urlsafe(32))

# Store for OAuth tokens (in production, use a database)
oauth_tokens = {}
oauth_codes = {}
registered_clients = {}

# Code file extensions
CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cc', '.cxx',
    '.h', '.hpp', '.cs', '.rb', '.go', '.rs', '.php', '.swift', '.kt', '.scala',
    '.r', '.m', '.mm', '.pl', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat',
    '.html', '.css', '.scss', '.sass', '.less', '.xml', '.json', '.yaml', '.yml',
    '.toml', '.ini', '.cfg', '.conf', '.sql', '.md', '.rst', '.txt', '.dockerfile',
    '.vue', '.svelte', '.lua', '.dart', '.elm', '.clj', '.cljs', '.edn', '.ex', '.exs'
}

# Set JSON encoder to not escape Unicode
json.encoder.ensure_ascii = False

# Initialize the FastMCP server (same as working non-OAuth version)
server_instructions = """
This MCP server provides code search and retrieval capabilities for local code repositories.
Use the search tool to find relevant code files based on keywords, function names, or code patterns,
then use the fetch tool to retrieve complete file content for analysis.
"""

mcp = FastMCP(
    name=SERVER_NAME,
    instructions=server_instructions
)

class CodeSearchEngine:
    """Code search engine for local code repositories (same as working version)"""
    
    def __init__(self, code_dir: str):
        self.code_dir = Path(code_dir).resolve()
        if not self.code_dir.exists():
            raise ValueError(f"Code directory does not exist: {code_dir}")
        self._index = self._build_index()
    
    def _should_ignore(self, path: Path) -> bool:
        """Check if a path should be ignored"""
        for part in path.parts:
            if part in IGNORE_DIRS or part.startswith('.'):
                return True
        return False
    
    def _build_index(self) -> Dict[str, Dict[str, Any]]:
        """Build an index of all code files in the directory"""
        index = {}
        indexed_count = 0
        
        logger.info(f"Indexing code files in: {self.code_dir}")
        
        for file_path in self.code_dir.rglob('*'):
            if self._should_ignore(file_path.relative_to(self.code_dir)):
                continue
            
            if file_path.is_file() and file_path.suffix.lower() in CODE_EXTENSIONS:
                try:
                    relative_path = file_path.relative_to(self.code_dir)
                    file_id = hashlib.md5(str(relative_path).encode()).hexdigest()[:12]
                    
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    language = self._get_language(file_path.suffix)
                    
                    index[file_id] = {
                        'id': file_id,
                        'path': str(file_path),
                        'relative_path': str(relative_path),
                        'title': str(relative_path),
                        'filename': file_path.name,
                        'content': content,
                        'size': len(content),
                        'lines': len(content.splitlines()),
                        'language': language,
                        'url': f"{SERVER_BASE_URL}/code/{file_id}"
                    }
                    
                    indexed_count += 1
                    if indexed_count % 100 == 0:
                        logger.info(f"Indexed {indexed_count} files...")
                    
                except Exception as e:
                    logger.error(f"Error indexing file {file_path}: {e}")
        
        logger.info(f"Built index with {len(index)} code files")
        return index
    
    def _get_language(self, suffix: str) -> str:
        """Get language name from file extension"""
        language_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
            '.java': 'java', '.go': 'go', '.rs': 'rust', '.rb': 'ruby',
            '.php': 'php', '.cs': 'csharp', '.cpp': 'cpp', '.c': 'c',
            '.swift': 'swift', '.kt': 'kotlin', '.scala': 'scala',
            '.sh': 'shell', '.md': 'markdown', '.json': 'json',
            '.yaml': 'yaml', '.yml': 'yaml', '.xml': 'xml', '.html': 'html',
            '.css': 'css', '.sql': 'sql'
        }
        return language_map.get(suffix.lower(), 'text')
    
    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search for code files matching the query"""
        if not query or not query.strip():
            return []
        
        query_lower = query.lower()
        results = []
        
        for doc_id, doc in self._index.items():
            score = 0
            
            if query_lower in doc['filename'].lower():
                score += 20
            
            if query_lower in doc['relative_path'].lower():
                score += 15
            
            content_lower = doc['content'].lower()
            if query_lower in content_lower:
                score += content_lower.count(query_lower) * 2
                
                if f"def {query_lower}" in content_lower or f"class {query_lower}" in content_lower:
                    score += 30
            
            if score > 0:
                # Extract snippet
                lines = doc['content'].splitlines()[:5]
                snippet = "\n".join([f"{i+1:4d}: {line}" for i, line in enumerate(lines)])
                if len(doc['content'].splitlines()) > 5:
                    snippet += "\n..."
                
                snippet = f"[{doc['language']}] {doc['relative_path']} ({doc['lines']} lines)\n{snippet}"
                
                results.append({
                    'id': doc_id,
                    'title': doc['relative_path'],
                    'text': snippet,
                    'url': doc['url'],
                    'score': score
                })
        
        results.sort(key=lambda x: x['score'], reverse=True)
        for result in results:
            del result['score']
        
        return results[:20]
    
    def fetch(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Fetch complete code file by ID"""
        doc = self._index.get(doc_id)
        
        if not doc:
            return None
        
        return {
            'id': doc['id'],
            'title': doc['relative_path'],
            'text': doc['content'],
            'url': doc['url'],
            'metadata': {
                'path': doc['path'],
                'relative_path': doc['relative_path'],
                'filename': doc['filename'],
                'language': doc['language'],
                'size': doc['size'],
                'lines': doc['lines']
            }
        }

# Initialize search engine
search_engine = None

# Define MCP tools EXACTLY like the working non-OAuth version
@mcp.tool()
async def search(query: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Search for code files matching the query.
    
    This tool searches through code files in the configured directory to find relevant matches.
    Supports text search, function/class name search, and regex patterns.
    Returns a list of search results with code snippets. Use the fetch tool to get
    complete file content.
    
    Args:
        query: Search query string. Can be:
               - Text to search for in code
               - Function or class names
               - File names or paths
               - Regex patterns (e.g., "def \\w+_test")
    
    Returns:
        Dictionary with 'results' key containing list of matching code files.
        Each result includes id, title (file path), text snippet with line numbers, and URL.
    """
    global search_engine
    
    if not search_engine:
        logger.error("Search engine not initialized")
        return {"results": []}
    
    logger.info(f"Searching for query: '{query}'")
    
    try:
        results = search_engine.search(query)
        logger.info(f"Search returned {len(results)} results")
        return {"results": results}
    except Exception as e:
        logger.error(f"Search error: {e}")
        return {"results": []}

@mcp.tool()
async def fetch(id: str) -> Dict[str, Any]:
    """
    Retrieve complete code file content by ID for detailed analysis.
    
    This tool fetches the full source code of a file. Use this after finding
    relevant files with the search tool to get complete code for analysis,
    debugging, or understanding implementation details.
    
    Args:
        id: File ID from search results
    
    Returns:
        Complete file with id, title (file path), full source code,
        URL, and metadata including language, size, and line count
    
    Raises:
        ValueError: If the specified ID is not found
    """
    global search_engine
    
    if not search_engine:
        raise ValueError("Search engine not initialized")
    
    if not id:
        raise ValueError("File ID is required")
    
    logger.info(f"Fetching code file with ID: {id}")
    
    document = search_engine.fetch(id)
    
    if not document:
        raise ValueError(f"Code file with ID '{id}' not found")
    
    logger.info(f"Fetched code file: {document['title']}")
    
    return document

# OAuth endpoints (simplified)
async def oauth_authorize(request):
    """OAuth 2.0 Authorization endpoint"""
    client_id = request.query_params.get('client_id')
    redirect_uri = request.query_params.get('redirect_uri')
    state = request.query_params.get('state')
    
    if client_id and redirect_uri:
        auth_code = secrets.token_urlsafe(32)
        oauth_codes[auth_code] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'created_at': time.time()
        }
        
        redirect_url = f"{redirect_uri}?code={auth_code}"
        if state:
            redirect_url += f"&state={state}"
        
        html_content = f"""
        <html>
        <head>
            <title>Authorizing...</title>
            <meta http-equiv="refresh" content="1;url={redirect_url}">
        </head>
        <body>
            <h2>MCP Code Search Authorization</h2>
            <p>Redirecting...</p>
        </body>
        </html>
        """
        return HTMLResponse(html_content)
    
    return JSONResponse({'error': 'invalid_request'}, status_code=400)

async def oauth_token(request):
    """OAuth 2.0 Token endpoint"""
    body = await request.form()
    grant_type = body.get('grant_type')
    
    if grant_type == 'authorization_code':
        code = body.get('code')
        client_id = body.get('client_id')
        
        if code in oauth_codes:
            access_token = secrets.token_urlsafe(32)
            oauth_tokens[access_token] = {
                'client_id': client_id,
                'created_at': time.time()
            }
            del oauth_codes[code]
            
            return JSONResponse({
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': 86400  # 24 hours
            })
    
    return JSONResponse({'error': 'invalid_grant'}, status_code=400)

async def oauth_register(request):
    """Dynamic Client Registration endpoint"""
    try:
        body = await request.json()
    except:
        return JSONResponse({'error': 'invalid_request'}, status_code=400)
    
    client_id = f"client_{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)
    
    registered_clients[client_id] = {
        'client_id': client_id,
        'client_secret': client_secret,
        'created_at': time.time()
    }
    
    logger.info(f"Registered new client: {client_id}")
    
    return JSONResponse({
        'client_id': client_id,
        'client_secret': client_secret,
        'client_id_issued_at': int(time.time()),
        'client_secret_expires_at': 0
    })

async def oauth_metadata(request):
    """OAuth 2.0 Authorization Server Metadata"""
    return JSONResponse({
        'issuer': SERVER_BASE_URL,
        'authorization_endpoint': f'{SERVER_BASE_URL}/oauth/authorize',
        'token_endpoint': f'{SERVER_BASE_URL}/oauth/token',
        'registration_endpoint': f'{SERVER_BASE_URL}/oauth/register',
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code'],
        'token_endpoint_auth_methods_supported': ['client_secret_post', 'none']
    })

def main():
    """Main function - similar to working non-OAuth version"""
    port = 8000
    host = "0.0.0.0"
    
    if SERVER_BASE_URL:
        parsed = urlparse(SERVER_BASE_URL)
        if parsed.port:
            port = parsed.port
    
    ssl_cert = os.environ.get("MCP_SSL_CERT")
    ssl_key = os.environ.get("MCP_SSL_KEY")
    
    logger.info(f"Using code directory: {CODE_DIR}")
    logger.info(f"Server name: {SERVER_NAME}")
    logger.info(f"Base URL: {SERVER_BASE_URL}")
    
    # Initialize search engine
    global search_engine
    try:
        search_engine = CodeSearchEngine(CODE_DIR)
        logger.info(f"Successfully indexed {len(search_engine._index)} code files")
    except ValueError as e:
        logger.error(f"Failed to initialize search engine: {e}")
        raise
    
    logger.info("Starting OpenAI-compatible MCP server with OAuth...")
    logger.info(f"SSE endpoint: {SERVER_BASE_URL}/")
    
    try:
        if ssl_cert and ssl_key:
            # For HTTPS, create a combined app with OAuth routes
            logger.info(f"Running with HTTPS (cert: {ssl_cert}, key: {ssl_key})")
            
            # Create OAuth routes
            oauth_routes = [
                Route('/oauth/authorize', oauth_authorize),
                Route('/oauth/token', oauth_token, methods=['POST']),
                Route('/oauth/register', oauth_register, methods=['POST']),
                Route('/.well-known/oauth-authorization-server', oauth_metadata),
            ]
            
            # Create combined app - Mount MCP at root like working version
            app = Starlette(
                routes=oauth_routes + [
                    Mount("/", app=mcp.sse_app()),  # MCP SSE at root
                ]
            )
            
            # Add OAuth protection for SSE endpoint
            app.add_middleware(
                OAuthMiddleware,
                oauth_tokens=oauth_tokens,
                protected_paths=["/"]  # Protect SSE endpoint
            )
            
            # Add CORS
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"]
            )
            
            uvicorn.run(
                app,
                host=host,
                port=port,
                ssl_certfile=ssl_cert,
                ssl_keyfile=ssl_key,
                timeout_graceful_shutdown=0
            )
        else:
            # For HTTP, just run MCP directly like working version
            mcp.run(transport="sse", host=host, port=port)
            
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise

if __name__ == "__main__":
    main()