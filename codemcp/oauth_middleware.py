"""
OAuth Authentication Middleware for MCP Server
"""

import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class OAuthMiddleware(BaseHTTPMiddleware):
    """Middleware to verify OAuth tokens for protected endpoints"""
    
    def __init__(self, app, oauth_tokens, protected_paths=None):
        super().__init__(app)
        self.oauth_tokens = oauth_tokens
        self.protected_paths = protected_paths or ['/']
    
    async def dispatch(self, request, call_next):
        # Check if this path needs protection
        path = request.url.path
        needs_auth = any(path.startswith(p) for p in self.protected_paths)
        
        # Skip auth for OAuth endpoints themselves
        if path.startswith('/oauth/') or path.startswith('/.well-known/'):
            return await call_next(request)
        
        if needs_auth:
            # Check for Bearer token
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                logger.warning(f"Missing Bearer token for protected path: {path}")
                return JSONResponse(
                    {"error": "unauthorized", "message": "Bearer token required"},
                    status_code=401
                )
            
            token = auth_header[7:]  # Remove "Bearer " prefix
            
            # Verify token exists and is valid
            if token not in self.oauth_tokens:
                logger.warning(f"Invalid token for protected path: {path}")
                return JSONResponse(
                    {"error": "invalid_token", "message": "Invalid or expired token"},
                    status_code=401
                )
            
            # Token is valid, proceed
            logger.info(f"Valid token for path: {path}")
        
        return await call_next(request)