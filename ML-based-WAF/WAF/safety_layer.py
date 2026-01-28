'''Safety layer for RL-based WAF.

This module implements hard constraints to prevent catastrophic false positives.
It acts as a safety net that can override RL agent decisions when necessary.

Purpose: Ensure the RL agent never learns dangerous policies that could:
- Block legitimate admin access
- Deny service to internal users
- Interfere with critical endpoints
'''

from rl_agent import Action
import re


class SafetyLayer:
    """Applies hard constraints to prevent dangerous RL decisions.
    
    Rules enforced:
    1. Never auto-BLOCK admin endpoints
    2. Internal IPs use CHALLENGE instead of BLOCK
    3. Known safe patterns always ALLOW
    4. Critical endpoints have restricted actions
    """
    
    # Endpoints that should never be blocked
    PROTECTED_ENDPOINTS = [
        r'/admin.*',
        r'/api/auth.*',
        r'/health.*',
        r'/metrics.*'
    ]
    
    # Internal IP ranges (private networks)
    INTERNAL_IP_PATTERNS = [
        r'^127\.',           # localhost
        r'^192\.168\.',      # private class C
        r'^10\.',            # private class A
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',  # private class B
        r'^::1$',            # IPv6 localhost
        r'^fe80:',           # IPv6 link-local
    ]
    
    def __init__(self):
        """Initialize the safety layer."""
        # Compile regex patterns for efficiency
        self.protected_endpoint_patterns = [
            re.compile(pattern) for pattern in self.PROTECTED_ENDPOINTS
        ]
        self.internal_ip_patterns = [
            re.compile(pattern) for pattern in self.INTERNAL_IP_PATTERNS
        ]
    
    def apply_constraints(self, action, endpoint=None, origin=None, context=None):
        """Apply safety constraints to an RL agent's chosen action.
        
        Args:
            action: Action chosen by RL agent
            endpoint: Request endpoint/path (e.g., '/api/user')
            origin: Source IP address
            context: Additional context dict (optional)
            
        Returns:
            Action: Potentially modified action that satisfies constraints
        """
        original_action = action
        
        # Rule 1: Never BLOCK protected endpoints
        if endpoint and self._is_protected_endpoint(endpoint):
            if action == Action.BLOCK:
                action = Action.CHALLENGE  # Downgrade to CHALLENGE
        
        # Rule 2: Internal IPs should use CHALLENGE instead of BLOCK
        if origin and self._is_internal_ip(origin):
            if action == Action.BLOCK:
                action = Action.CHALLENGE  # Softer action for internal users
        
        # Rule 3: Known safe patterns should always ALLOW
        if context and context.get('is_known_safe', False):
            action = Action.ALLOW
        
        # Rule 4: Health check endpoints should always ALLOW
        if endpoint and (endpoint == '/health' or endpoint == '/ping'):
            action = Action.ALLOW
        
        return action
    
    def _is_protected_endpoint(self, endpoint):
        """Check if endpoint matches protected patterns.
        
        Args:
            endpoint: Request path
            
        Returns:
            bool: True if endpoint is protected
        """
        for pattern in self.protected_endpoint_patterns:
            if pattern.match(endpoint):
                return True
        return False
    
    def _is_internal_ip(self, ip):
        """Check if IP is from internal network.
        
        Args:
            ip: IP address string
            
        Returns:
            bool: True if IP is internal
        """
        for pattern in self.internal_ip_patterns:
            if pattern.match(ip):
                return True
        return False
    
    def get_allowed_actions(self, endpoint=None, origin=None):
        """Get list of allowed actions for given context.
        
        Useful for restricting RL agent's action space in certain situations.
        
        Args:
            endpoint: Request endpoint/path
            origin: Source IP address
            
        Returns:
            list[Action]: Actions that are allowed in this context
        """
        allowed = list(Action)  # Start with all actions
        
        # Remove BLOCK for protected endpoints
        if endpoint and self._is_protected_endpoint(endpoint):
            if Action.BLOCK in allowed:
                allowed.remove(Action.BLOCK)
        
        # Remove BLOCK for internal IPs
        if origin and self._is_internal_ip(origin):
            if Action.BLOCK in allowed:
                allowed.remove(Action.BLOCK)
        
        return allowed
