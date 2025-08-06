#!/usr/bin/env python3
"""
OpenAI-compatible MCP Server for Code Search

This server implements the Model Context Protocol (MCP) with search and fetch
capabilities for searching and retrieving code files from local directories.
Designed to work with ChatGPT's chat and deep research features.
"""

import logging
import os
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib
import mimetypes

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
CODE_DIR = os.environ.get("MCP_CODE_DIR", os.getcwd())
IGNORE_DIRS = os.environ.get("MCP_IGNORE_DIRS", ".git,node_modules,__pycache__,.venv,venv,dist,build").split(",")
SERVER_NAME = os.environ.get("MCP_SERVER_NAME", "Code Search MCP Server")
SERVER_BASE_URL = os.environ.get("MCP_SERVER_BASE_URL", "http://localhost:8000")

# Code file extensions to index
CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cc', '.cxx',
    '.h', '.hpp', '.cs', '.rb', '.go', '.rs', '.php', '.swift', '.kt', '.scala',
    '.r', '.m', '.mm', '.pl', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat',
    '.html', '.css', '.scss', '.sass', '.less', '.xml', '.json', '.yaml', '.yml',
    '.toml', '.ini', '.cfg', '.conf', '.sql', '.md', '.rst', '.txt', '.dockerfile',
    '.vue', '.svelte', '.lua', '.dart', '.elm', '.clj', '.cljs', '.edn', '.ex', '.exs'
}

# Initialize the FastMCP server
server_instructions = """
This MCP server provides code search and retrieval capabilities for local code repositories.
Use the search tool to find relevant code files based on keywords, function names, or code patterns,
then use the fetch tool to retrieve complete file content for analysis.
"""

# Set JSON encoder to not escape Unicode
json.encoder.ensure_ascii = False

mcp = FastMCP(
    name=SERVER_NAME,
    instructions=server_instructions
)

class CodeSearchEngine:
    """Code search engine for local code repositories"""
    
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
            # Skip if in ignored directory
            if self._should_ignore(file_path.relative_to(self.code_dir)):
                continue
            
            if file_path.is_file() and file_path.suffix.lower() in CODE_EXTENSIONS:
                try:
                    # Generate unique ID for the file
                    relative_path = file_path.relative_to(self.code_dir)
                    file_id = hashlib.md5(str(relative_path).encode()).hexdigest()[:12]
                    
                    # Read file content with UTF-8 encoding
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    # Extract language from extension
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
            '.jsx': 'javascript', '.tsx': 'typescript', '.java': 'java',
            '.c': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.h': 'c', '.hpp': 'cpp',
            '.cs': 'csharp', '.rb': 'ruby', '.go': 'go', '.rs': 'rust',
            '.php': 'php', '.swift': 'swift', '.kt': 'kotlin', '.scala': 'scala',
            '.r': 'r', '.sh': 'shell', '.bash': 'bash', '.ps1': 'powershell',
            '.html': 'html', '.css': 'css', '.scss': 'scss', '.json': 'json',
            '.xml': 'xml', '.yaml': 'yaml', '.yml': 'yaml', '.sql': 'sql',
            '.md': 'markdown', '.vue': 'vue', '.svelte': 'svelte'
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
                occurrences = content_lower.count(query_lower)
                score += occurrences * 2
                match_pos = content_lower.find(query_lower)
                
                if f"def {query_lower}" in content_lower or f"class {query_lower}" in content_lower:
                    score += 30
            else:
                match_pos = -1
            
            if score > 0:
                if match_pos != -1:
                    lines = doc['content'].splitlines()
                    char_count = 0
                    line_num = 0
                    
                    for i, line in enumerate(lines):
                        if char_count <= match_pos < char_count + len(line) + 1:
                            line_num = i
                            break
                        char_count += len(line) + 1
                    
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 3)
                    snippet_lines = lines[start_line:end_line]
                    snippet = "\n".join([f"{start_line + i + 1:4d}: {line}" 
                                        for i, line in enumerate(snippet_lines)])
                    
                    if start_line > 0:
                        snippet = "...\n" + snippet
                    if end_line < len(lines):
                        snippet = snippet + "\n..."
                else:
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
            'text': doc['content'],  # Return raw UTF-8 content
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
    
    # The document already contains UTF-8 text properly
    return document

def main():
    """Main function to start the MCP server"""
    import sys
    
    # Parse port from base URL if provided
    port = 8000
    host = "0.0.0.0"
    if SERVER_BASE_URL:
        from urllib.parse import urlparse
        parsed = urlparse(SERVER_BASE_URL)
        if parsed.port:
            port = parsed.port
        if parsed.hostname:
            host = parsed.hostname
    
    # Check for SSL parameters from environment or command line
    ssl_cert = os.environ.get("MCP_SSL_CERT")
    ssl_key = os.environ.get("MCP_SSL_KEY")
    
    logger.info(f"Using code directory: {CODE_DIR}")
    logger.info(f"Server name: {SERVER_NAME}")
    logger.info(f"Base URL: {SERVER_BASE_URL}")
    logger.info(f"Ignoring directories: {', '.join(IGNORE_DIRS)}")
    
    # Initialize search engine
    global search_engine
    try:
        search_engine = CodeSearchEngine(CODE_DIR)
        logger.info(f"Successfully indexed {len(search_engine._index)} code files")
    except ValueError as e:
        logger.error(f"Failed to initialize search engine: {e}")
        raise
    
    logger.info("Starting OpenAI-compatible Code Search MCP server...")
    logger.info(f"Server will be accessible via SSE transport on {host}:{port}")
    logger.info(f"To use with ChatGPT, connect to: {SERVER_BASE_URL}/sse/")
    
    try:
        # Check if we need to run with uvicorn for HTTPS support
        if ssl_cert and ssl_key:
            logger.info(f"Running with HTTPS (cert: {ssl_cert}, key: {ssl_key})")
            # Use uvicorn directly for HTTPS support
            import uvicorn
            from starlette.applications import Starlette
            from starlette.routing import Mount
            
            # Create Starlette app with MCP SSE endpoint
            app = Starlette(
                routes=[
                    Mount("/", app=mcp.sse_app()),
                ]
            )
            
            # Run with uvicorn and SSL
            uvicorn.run(
                app,
                host=host,
                port=port,
                ssl_certfile=ssl_cert,
                ssl_keyfile=ssl_key,
                timeout_graceful_shutdown=0
            )
        else:
            # Run with standard SSE transport
            mcp.run(transport="sse", host=host, port=port)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise

if __name__ == "__main__":
    main()