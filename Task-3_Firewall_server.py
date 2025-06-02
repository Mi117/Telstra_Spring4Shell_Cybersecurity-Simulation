#!/usr/bin/env python3
"""
Firewall HTTP Server to mitigate Spring4Shell (CVE-2022-22965) vulnerability.
This server filters incoming traffic to block potential exploitation attempts.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import re
import json
import logging
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Spring4ShellFirewallHandler(BaseHTTPRequestHandler):
    """HTTP request handler that implements Spring4Shell mitigation rules."""
    
    # Patterns that indicate Spring4Shell exploitation attempts
    MALICIOUS_PATTERNS = [
        # Direct class manipulation patterns
        r'class\.module\.classLoader',
        r'class\.classLoader',
        r'\.classLoader\.resources',
        r'\.classLoader\.parent',
        r'\.classLoader\.URLs',
        r'\.classLoader\.getResource',
        
        # Tomcat-specific patterns
        r'class\.module\.classLoader\.resources\.context\.parent\.pipeline',
        r'class\.module\.classLoader\.resources\.context\.configFile',
        r'\.pipeline\.first\.pattern',
        r'\.pipeline\.first\.suffix',
        r'\.pipeline\.first\.directory',
        r'\.pipeline\.first\.prefix',
        
        # JSP compilation and execution patterns
        r'\.suffix=\.jsp',
        r'\.directory=webapps/ROOT',
        r'\.prefix=tomcatwar',
        r'\.pattern=%\{.*\}',
        
        # Other dangerous patterns
        r'accessLogValve',
        r'applicationContext',
        r'servletContext',
        r'\.getClass\(\)',
        r'Runtime\.getRuntime',
        r'ProcessBuilder',
        
        # Encoded variations
        r'%252e',  # Double-encoded dot
        r'%2e',    # URL-encoded dot
        r'%5c',    # URL-encoded backslash
        r'%2f',    # URL-encoded forward slash
    ]
    
    # Suspicious parameter names commonly used in Spring4Shell attacks
    SUSPICIOUS_PARAMS = [
        'class.module.classLoader.resources.context.parent.pipeline.first.pattern',
        'class.module.classLoader.resources.context.parent.pipeline.first.suffix',
        'class.module.classLoader.resources.context.parent.pipeline.first.directory',
        'class.module.classLoader.resources.context.parent.pipeline.first.prefix',
        'class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat',
        'class.classLoader.resources.context.parent.pipeline.first.pattern',
        'class.classLoader.resources.context.parent.pipeline.first.suffix',
        'class.classLoader.resources.context.parent.pipeline.first.directory',
        'class.classLoader.resources.context.parent.pipeline.first.prefix',
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.MALICIOUS_PATTERNS]
    
    def do_GET(self):
        """Handle GET requests."""
        self._handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests."""
        self._handle_request('POST')
    
    def do_PUT(self):
        """Handle PUT requests."""
        self._handle_request('PUT')
    
    def do_DELETE(self):
        """Handle DELETE requests."""
        self._handle_request('DELETE')
    
    def _handle_request(self, method: str):
        """Main request handling logic with Spring4Shell filtering."""
        try:
            # Parse the request
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Get request body for POST/PUT requests
            request_body = ""
            if method in ['POST', 'PUT']:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    request_body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            
            # Check for Spring4Shell attack patterns
            if self._is_spring4shell_attack(parsed_url, query_params, request_body, self.headers):
                self._block_request("Spring4Shell attack detected")
                return
            
            # If no malicious patterns detected, allow the request
            self._allow_request(method)
            
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            self._send_error_response(500, "Internal server error")
    
    def _is_spring4shell_attack(self, parsed_url, query_params: Dict, body: str, headers) -> bool:
        """
        Detect Spring4Shell attack patterns in the request.
        
        Args:
            parsed_url: Parsed URL object
            query_params: Dictionary of query parameters
            body: Request body content
            headers: Request headers
            
        Returns:
            bool: True if attack patterns are detected, False otherwise
        """
        # Check URL path
        if self._contains_malicious_patterns(parsed_url.path):
            logger.warning(f"Malicious pattern detected in URL path: {parsed_url.path}")
            return True
        
        # Check query string
        if self._contains_malicious_patterns(parsed_url.query):
            logger.warning(f"Malicious pattern detected in query string: {parsed_url.query}")
            return True
        
        # Check individual query parameters
        for param_name, param_values in query_params.items():
            # Check parameter name
            if param_name.lower() in [p.lower() for p in self.SUSPICIOUS_PARAMS]:
                logger.warning(f"Suspicious parameter name detected: {param_name}")
                return True
            
            if self._contains_malicious_patterns(param_name):
                logger.warning(f"Malicious pattern in parameter name: {param_name}")
                return True
            
            # Check parameter values
            for value in param_values:
                if self._contains_malicious_patterns(value):
                    logger.warning(f"Malicious pattern in parameter value: {param_name}={value}")
                    return True
        
        # Check request body
        if body and self._contains_malicious_patterns(body):
            logger.warning(f"Malicious pattern detected in request body")
            return True
        
        # Check headers
        for header_name, header_value in headers.items():
            if self._contains_malicious_patterns(f"{header_name}: {header_value}"):
                logger.warning(f"Malicious pattern detected in header: {header_name}")
                return True
        
        # Additional checks for form data in POST bodies
        if body:
            try:
                # Try to parse as form data
                form_data = urllib.parse.parse_qs(body)
                for param_name, param_values in form_data.items():
                    if param_name.lower() in [p.lower() for p in self.SUSPICIOUS_PARAMS]:
                        logger.warning(f"Suspicious form parameter detected: {param_name}")
                        return True
                    
                    for value in param_values:
                        if self._contains_malicious_patterns(value):
                            logger.warning(f"Malicious pattern in form data: {param_name}={value}")
                            return True
            except:
                # If parsing fails, the body was already checked as plain text above
                pass
        
        return False
    
    def _contains_malicious_patterns(self, text: str) -> bool:
        """Check if text contains any malicious patterns."""
        if not text:
            return False
        
        # URL decode the text to catch encoded attacks
        decoded_text = urllib.parse.unquote_plus(text)
        
        # Check both original and decoded text
        for pattern in self.compiled_patterns:
            if pattern.search(text) or pattern.search(decoded_text):
                return True
        
        return False
    
    def _block_request(self, reason: str):
        """Block the request and send a 403 Forbidden response."""
        logger.warning(f"BLOCKED REQUEST - {reason} - {self.client_address[0]} - {self.command} {self.path}")
        self._send_error_response(403, f"Forbidden: {reason}")
    
    def _allow_request(self, method: str):
        """Allow the request and send a success response."""
        logger.info(f"ALLOWED REQUEST - {self.client_address[0]} - {method} {self.path}")
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            "status": "allowed",
            "message": "Request passed firewall filtering",
            "method": method,
            "path": self.path,
            "timestamp": self.date_time_string()
        }
        
        self.wfile.write(json.dumps(response, indent=2).encode())
    
    def _send_error_response(self, code: int, message: str):
        """Send an error response."""
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            "status": "error",
            "code": code,
            "message": message,
            "timestamp": self.date_time_string()
        }
        
        self.wfile.write(json.dumps(response, indent=2).encode())
    
    def log_message(self, format, *args):
        """Override default logging to use our logger."""
        logger.info(f"{self.client_address[0]} - {format % args}")

def run_firewall_server(host='localhost', port=8080):
    """Run the firewall HTTP server."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, Spring4ShellFirewallHandler)
    
    logger.info(f"Spring4Shell Firewall Server starting on {host}:{port}")
    logger.info("Press Ctrl+C to stop the server")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        httpd.server_close()

if __name__ == '__main__':
    run_firewall_server()