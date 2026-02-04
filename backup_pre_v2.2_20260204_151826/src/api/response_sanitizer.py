
import html
import re
from typing import Any, Dict

class ResponseSanitizer:
    """
    Sanitiza responses para prevenir XSS (Cross-Site Scripting).
    
    Princípios:
    1. Escape HTML entities
    2. Remove scripts
    3. Sanitize URLs
    4. Content-Type headers corretos
    """
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """
        Escape HTML entities (previne XSS).
        
        Exemplos:
        - "<script>alert('xss')</script>" → "&lt;script&gt;alert('xss')&lt;/script&gt;"
        - "Hello <b>World</b>" → "Hello &lt;b&gt;World&lt;/b&gt;"
        """
        return html.escape(text, quote=True)
    
    @staticmethod
    def remove_scripts(text: str) -> str:
        """
        Remove tags <script> (defense in depth).
        """
        # Remove script tags (case-insensitive)
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove event handlers (onclick, onerror, etc)
        text = re.sub(r'\s*on\w+\s*=\s*["\'].*?["\']', '', text, flags=re.IGNORECASE)
        
        # Remove javascript: URLs
        text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        
        return text
    
    @staticmethod
    def sanitize_json_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitiza recursivamente um JSON response.
        """
        if isinstance(data, dict):
            return {
                key: ResponseSanitizer.sanitize_json_response(value)
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [ResponseSanitizer.sanitize_json_response(item) for item in data]
        elif isinstance(data, str):
            # Sanitiza strings (HTML escape)
            return ResponseSanitizer.sanitize_html(data)
        else:
            return data
    
    @staticmethod
    def get_safe_headers() -> Dict[str, str]:
        """
        Headers de segurança (XSS, clickjacking, etc).
        """
        return {
            # XSS Protection
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            
            # Content Security Policy
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            ),
            
            # HTTPS enforcement
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions policy
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        }

# FastAPI middleware para aplicar headers
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Adiciona headers de segurança
        for key, value in ResponseSanitizer.get_safe_headers().items():
            response.headers[key] = value
        
        return response

# Uso no FastAPI
from fastapi import FastAPI

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)

@app.post("/api/v2/validate")
async def validate_input(text: str):
    # Process input...
    result = {
        "action": "BLOCK",
        "rationale": "CPF detected in general context",
        "user_input": text,  # ← DANGER: XSS se não sanitizado!
    }
    
    # Sanitiza response
    safe_result = ResponseSanitizer.sanitize_json_response(result)
    
    return safe_result