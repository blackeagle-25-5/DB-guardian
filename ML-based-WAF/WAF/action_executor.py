'''Action executor for RL-based WAF.

This module executes the actions chosen by the RL agent.
Each action has a specific handler that modifies or controls the request flow.
'''

from rl_agent import Action
import re
import time


class ActionExecutor:
    """Executes WAF actions on HTTP requests.
    
    Actions:
    - ALLOW: Forward request unchanged
    - LOG_ONLY: Forward but mark for logging
    - SANITIZE: Remove SQL keywords/quotes before forwarding
    - CHALLENGE: Mark for CAPTCHA/re-auth (implementation-specific)
    - THROTTLE: Add delay or mark for rate limiting
    - BLOCK: Mark request as blocked (actual blocking done by caller)
    """
    
    # SQL keywords to remove during sanitization
    SQL_KEYWORDS = [
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'create', 'alter', 'exec', 'execute', 'script', 'javascript'
    ]
    
    def __init__(self, throttle_delay_ms=1000):
        """Initialize the action executor.
        
        Args:
            throttle_delay_ms: Delay in milliseconds for THROTTLE action
        """
        self.throttle_delay_ms = throttle_delay_ms
        self.execution_count = {action: 0 for action in Action}
    
    def execute(self, action, request_data):
        """Execute the given action on request data.
        
        Args:
            action: Action to execute
            request_data: dict with request fields (request, body, headers)
            
        Returns:
            dict: Result with keys:
                - 'action': Action that was executed
                - 'allowed': bool, whether request should proceed
                - 'modified': bool, whether request was modified
                - 'request_data': potentially modified request data
                - 'metadata': additional info about execution
        """
        self.execution_count[action] += 1
        
        if action == Action.ALLOW:
            return self._execute_allow(request_data)
        elif action == Action.LOG_ONLY:
            return self._execute_log_only(request_data)
        elif action == Action.SANITIZE:
            return self._execute_sanitize(request_data)
        elif action == Action.CHALLENGE:
            return self._execute_challenge(request_data)
        elif action == Action.THROTTLE:
            return self._execute_throttle(request_data)
        elif action == Action.BLOCK:
            return self._execute_block(request_data)
        else:
            # Unknown action - default to BLOCK for safety
            return self._execute_block(request_data)
    
    def _execute_allow(self, request_data):
        """Allow request to proceed unchanged."""
        return {
            'action': Action.ALLOW,
            'allowed': True,
            'modified': False,
            'request_data': request_data,
            'metadata': {'reason': 'Request allowed by policy'}
        }
    
    def _execute_log_only(self, request_data):
        """Allow request but mark for detailed logging."""
        return {
            'action': Action.LOG_ONLY,
            'allowed': True,
            'modified': False,
            'request_data': request_data,
            'metadata': {
                'reason': 'Request allowed but flagged for review',
                'requires_logging': True
            }
        }
    
    def _execute_sanitize(self, request_data):
        """Remove SQL keywords and dangerous characters before forwarding."""
        sanitized_data = request_data.copy()
        modified = False
        
        # Sanitize request path
        if 'request' in sanitized_data and sanitized_data['request']:
            original = sanitized_data['request']
            sanitized = self._sanitize_text(original)
            if sanitized != original:
                sanitized_data['request'] = sanitized
                modified = True
        
        # Sanitize body
        if 'body' in sanitized_data and sanitized_data['body']:
            original = sanitized_data['body']
            sanitized = self._sanitize_text(original)
            if sanitized != original:
                sanitized_data['body'] = sanitized
                modified = True
        
        return {
            'action': Action.SANITIZE,
            'allowed': True,
            'modified': modified,
            'request_data': sanitized_data,
            'metadata': {
                'reason': 'Request sanitized to remove SQL injection patterns',
                'sanitization_applied': modified
            }
        }
    
    def _sanitize_text(self, text):
        """Remove SQL keywords and dangerous characters from text.
        
        Args:
            text: Text to sanitize
            
        Returns:
            str: Sanitized text
        """
        if not text:
            return text
        
        sanitized = text
        
        # Remove SQL keywords (case-insensitive)
        for keyword in self.SQL_KEYWORDS:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            sanitized = pattern.sub('', sanitized)
        
        # Remove SQL comment patterns
        sanitized = sanitized.replace('--', '')
        sanitized = sanitized.replace('/*', '')
        sanitized = sanitized.replace('*/', '')
        
        # Remove excessive quotes (keep single quotes for legitimate use)
        # Only remove if there are multiple consecutive quotes
        sanitized = re.sub(r"'{2,}", "'", sanitized)
        sanitized = re.sub(r'"{2,}', '"', sanitized)
        
        # Remove semicolons (often used to chain SQL commands)
        sanitized = sanitized.replace(';', '')
        
        return sanitized
    
    def _execute_challenge(self, request_data):
        """Mark request for CAPTCHA or re-authentication.
        
        Note: Actual CAPTCHA implementation is application-specific.
        This just marks the request for challenge.
        """
        return {
            'action': Action.CHALLENGE,
            'allowed': False,  # Don't proceed until challenge is completed
            'modified': False,
            'request_data': request_data,
            'metadata': {
                'reason': 'Request requires additional verification',
                'challenge_required': True,
                'challenge_type': 'captcha'  # or 're-auth'
            }
        }
    
    def _execute_throttle(self, request_data):
        """Add delay to slow down potential attacker.
        
        Note: Actual rate limiting is application-specific.
        This adds a simple delay.
        """
        # Add delay
        time.sleep(self.throttle_delay_ms / 1000.0)
        
        return {
            'action': Action.THROTTLE,
            'allowed': True,
            'modified': False,
            'request_data': request_data,
            'metadata': {
                'reason': 'Request throttled due to suspicious activity',
                'delay_ms': self.throttle_delay_ms,
                'rate_limit_applied': True
            }
        }
    
    def _execute_block(self, request_data):
        """Block the request entirely."""
        return {
            'action': Action.BLOCK,
            'allowed': False,
            'modified': False,
            'request_data': request_data,
            'metadata': {
                'reason': 'Request blocked by security policy',
                'http_status': 403  # Forbidden
            }
        }
    
    def get_statistics(self):
        """Get execution statistics.
        
        Returns:
            dict: Count of each action executed
        """
        total = sum(self.execution_count.values())
        stats = {
            'total_executions': total,
            'action_counts': {
                action.value: count 
                for action, count in self.execution_count.items()
            }
        }
        
        # Add percentages
        if total > 0:
            stats['action_percentages'] = {
                action.value: (count / total) * 100
                for action, count in self.execution_count.items()
            }
        
        return stats
