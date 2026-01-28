'''Feature extraction module for RL-based WAF.

This module extracts numeric features from HTTP requests for use by the RL agent.
Features focus on SQL injection indicators and statistical properties.
'''

import urllib.parse
import re
import math
from collections import Counter
from request import Request


class FeatureExtractor:
    """Extracts numeric features from HTTP requests for RL decision-making."""
    
    # SQL keywords commonly used in injection attacks
    SQL_KEYWORDS = [
        'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
        'alter', 'exec', 'execute', 'script', 'javascript', 'onerror',
        'onload', 'alert', 'prompt', 'confirm', 'eval', 'expression'
    ]
    
    # SQL comment patterns
    SQL_COMMENTS = ['--', '/*', '*/', '#']
    
    def __init__(self):
        """Initialize the feature extractor."""
        pass
    
    def extract_features(self, req):
        """Extract feature vector from a Request object.
        
        Args:
            req: Request object containing HTTP request data
            
        Returns:
            dict: Feature vector with numeric values
        """
        if not isinstance(req, Request):
            raise TypeError("Object should be a Request!")
        
        features = {}
        
        # Combine all request parts for analysis
        combined_text = self._get_combined_text(req)
        
        if combined_text:
            # SQL injection indicators
            features['sql_keyword_count'] = self._count_sql_keywords(combined_text)
            features['quote_count'] = combined_text.count("'") + combined_text.count('"')
            features['semicolon_count'] = combined_text.count(';')
            features['comment_pattern_count'] = self._count_comment_patterns(combined_text)
            features['equals_count'] = combined_text.count('=')
            features['or_and_count'] = combined_text.lower().count(' or ') + combined_text.lower().count(' and ')
            
            # Statistical features
            features['length'] = len(combined_text)
            features['entropy'] = self._calculate_entropy(combined_text)
            features['special_char_ratio'] = self._calculate_special_char_ratio(combined_text)
            features['digit_ratio'] = self._calculate_digit_ratio(combined_text)
            features['uppercase_ratio'] = self._calculate_uppercase_ratio(combined_text)
            
            # URL encoding depth (multiple encoding layers)
            features['encoding_depth'] = self._calculate_encoding_depth(combined_text)
        else:
            # Empty request - all features are 0
            features = self._get_zero_features()
        
        # Request metadata features
        features['method_is_post'] = 1 if req.method == 'POST' else 0
        features['has_body'] = 1 if req.body and req.body.strip() else 0
        features['has_cookie'] = 1 if req.headers and 'Cookie' in req.headers else 0
        
        return features
    
    def _get_combined_text(self, req):
        """Combine all request parts into a single string for analysis.
        
        Args:
            req: Request object
            
        Returns:
            str: Combined and cleaned text
        """
        parts = []
        
        if req.request:
            parts.append(self._clean_text(req.request))
        
        if req.body:
            parts.append(self._clean_text(req.body))
        
        if req.headers:
            # Only analyze potentially dangerous headers
            dangerous_headers = ['Cookie', 'User_Agent', 'Referer']
            for header in dangerous_headers:
                if header in req.headers and req.headers[header]:
                    parts.append(self._clean_text(req.headers[header]))
        
        return ' '.join(parts)
    
    def _clean_text(self, text):
        """Clean and normalize text for analysis.
        
        Args:
            text: Raw text string
            
        Returns:
            str: Cleaned text
        """
        if not text:
            return ''
        
        # URL decode (multiple times to handle nested encoding)
        cleaned = self._unquote(text)
        
        # Remove newlines and normalize whitespace
        cleaned = cleaned.strip()
        cleaned = ' '.join(cleaned.splitlines())
        cleaned = ' '.join(cleaned.split())
        
        return cleaned
    
    def _unquote(self, text):
        """Recursively URL decode text.
        
        Args:
            text: URL-encoded text
            
        Returns:
            str: Decoded text
        """
        prev = text
        for _ in range(10):  # Max 10 levels of encoding
            decoded = urllib.parse.unquote_plus(prev)
            if decoded == prev:
                break
            prev = decoded
        return prev
    
    def _count_sql_keywords(self, text):
        """Count SQL keywords in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            int: Number of SQL keywords found
        """
        text_lower = text.lower()
        count = 0
        for keyword in self.SQL_KEYWORDS:
            # Use word boundaries to avoid false positives
            pattern = r'\b' + re.escape(keyword) + r'\b'
            count += len(re.findall(pattern, text_lower))
        return count
    
    def _count_comment_patterns(self, text):
        """Count SQL comment patterns in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            int: Number of comment patterns found
        """
        count = 0
        for pattern in self.SQL_COMMENTS:
            count += text.count(pattern)
        return count
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text.
        
        Higher entropy may indicate obfuscation or encoding.
        
        Args:
            text: Text to analyze
            
        Returns:
            float: Entropy value
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_special_char_ratio(self, text):
        """Calculate ratio of special characters to total characters.
        
        Args:
            text: Text to analyze
            
        Returns:
            float: Ratio between 0 and 1
        """
        if not text:
            return 0.0
        
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special_chars / len(text)
    
    def _calculate_digit_ratio(self, text):
        """Calculate ratio of digits to total characters.
        
        Args:
            text: Text to analyze
            
        Returns:
            float: Ratio between 0 and 1
        """
        if not text:
            return 0.0
        
        digits = sum(1 for c in text if c.isdigit())
        return digits / len(text)
    
    def _calculate_uppercase_ratio(self, text):
        """Calculate ratio of uppercase letters to total characters.
        
        Args:
            text: Text to analyze
            
        Returns:
            float: Ratio between 0 and 1
        """
        if not text:
            return 0.0
        
        uppercase = sum(1 for c in text if c.isupper())
        return uppercase / len(text)
    
    def _calculate_encoding_depth(self, text):
        """Calculate URL encoding depth (nested encoding layers).
        
        Args:
            text: Text to analyze
            
        Returns:
            int: Number of encoding layers
        """
        depth = 0
        prev = text
        
        for _ in range(10):
            decoded = urllib.parse.unquote_plus(prev)
            if decoded == prev:
                break
            depth += 1
            prev = decoded
        
        return depth
    
    def _get_zero_features(self):
        """Get feature vector with all zeros (for empty requests).
        
        Returns:
            dict: Feature vector with zero values
        """
        return {
            'sql_keyword_count': 0,
            'quote_count': 0,
            'semicolon_count': 0,
            'comment_pattern_count': 0,
            'equals_count': 0,
            'or_and_count': 0,
            'length': 0,
            'entropy': 0.0,
            'special_char_ratio': 0.0,
            'digit_ratio': 0.0,
            'uppercase_ratio': 0.0,
            'encoding_depth': 0,
            'method_is_post': 0,
            'has_body': 0,
            'has_cookie': 0
        }
