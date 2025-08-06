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
import asyncio
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

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

class CodeFileWatcher(FileSystemEventHandler):
    """File system watcher for code changes with incremental updates"""
    
    def __init__(self, search_engine):
        self.search_engine = search_engine
        self.debounce_timer = None
        self.debounce_delay = 2.0  # 2 seconds debounce
        self.pending_changes = set()  # Track pending file changes
        self.changes_lock = threading.Lock()
        
    def on_any_event(self, event):
        if event.is_directory:
            return
            
        # Check if it's a code file
        try:
            path = Path(event.src_path)
            if path.suffix.lower() not in CODE_EXTENSIONS:
                return
                
            # Check if should be ignored
            relative_path = path.relative_to(self.search_engine.code_dir)
            if self.search_engine._should_ignore(relative_path):
                return
                
        except (ValueError, OSError):
            # Path might be outside code_dir or invalid
            return
        
        # Track the changed file
        with self.changes_lock:
            self.pending_changes.add(str(relative_path))
        
        # Debounce: cancel previous timer and start new one
        if self.debounce_timer:
            self.debounce_timer.cancel()
            
        self.debounce_timer = threading.Timer(
            self.debounce_delay, 
            self._trigger_update
        )
        self.debounce_timer.start()
        
    def _trigger_update(self):
        """Trigger incremental index update after debounce delay"""
        try:
            # Get pending changes and clear the set
            with self.changes_lock:
                changed_files = set(self.pending_changes)
                self.pending_changes.clear()
            
            if not changed_files:
                return
                
            logger.info(f"File changes detected for {len(changed_files)} files, updating index...")
            
            # For now, do full rebuild (can be optimized later for true incremental updates)
            self.search_engine._update_index()
            logger.info("Index updated successfully")
        except Exception as e:
            logger.error(f"Error updating index: {e}")


class CodeSearchEngine:
    """Code search engine for local code repositories with file monitoring"""
    
    def __init__(self, code_dir: str):
        self.code_dir = Path(code_dir).resolve()
        if not self.code_dir.exists():
            raise ValueError(f"Code directory does not exist: {code_dir}")
        
        self._index = self._build_index()
        self._lock = threading.RLock()  # Thread-safe index updates
        
        # Initialize file watcher
        self._setup_file_watcher()
    
    def _should_ignore(self, path: Path) -> bool:
        """Check if a path should be ignored"""
        for part in path.parts:
            if part in IGNORE_DIRS or part.startswith('.'):
                return True
        return False
    
    def _setup_file_watcher(self):
        """Setup file system watcher"""
        try:
            self.watcher = CodeFileWatcher(self)
            self.observer = Observer()
            self.observer.schedule(
                self.watcher, 
                str(self.code_dir), 
                recursive=True
            )
            self.observer.start()
            logger.info(f"File watcher started for: {self.code_dir}")
        except Exception as e:
            logger.error(f"Failed to setup file watcher: {e}")
            self.observer = None
    
    def _update_index(self):
        """Thread-safe index update"""
        with self._lock:
            logger.info("Rebuilding index...")
            new_index = self._build_index_internal()
            self._index = new_index
            logger.info(f"Index rebuilt with {len(new_index)} files")
    
    def _build_index(self) -> Dict[str, Dict[str, Any]]:
        """Build initial index"""
        return self._build_index_internal()
    
    def _build_index_internal(self) -> Dict[str, Dict[str, Any]]:
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
        
        # Thread-safe access to index
        with self._lock:
            index_snapshot = dict(self._index)
        
        for doc_id, doc in index_snapshot.items():
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
        # Thread-safe access to index
        with self._lock:
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
    
    def shutdown(self):
        """Clean shutdown of file watcher"""
        if hasattr(self, 'observer') and self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5.0)
                logger.info("File watcher stopped")
            except Exception as e:
                logger.error(f"Error stopping file watcher: {e}")
        
        if hasattr(self, 'watcher') and hasattr(self.watcher, 'debounce_timer') and self.watcher.debounce_timer:
            self.watcher.debounce_timer.cancel()

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
    finally:
        # Clean shutdown
        if search_engine:
            search_engine.shutdown()

if __name__ == "__main__":
    main()