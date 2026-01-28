'''Reward calculation for RL-based WAF.

This module converts request outcomes into numeric rewards for the RL agent.
The reward signal guides the agent to learn optimal policies.

Reward Philosophy:
- Positive rewards for correct decisions (block attacks, allow legitimate traffic)
- Negative rewards for mistakes (false positives, false negatives)
- Penalties for high latency or resource usage
- Bonus for using less restrictive actions when safe
'''

from rl_agent import Action


class RewardCalculator:
    """Calculates rewards based on request outcomes.
    
    Reward structure:
    - Blocked real attack: +1.0 (good)
    - Allowed legitimate request: +0.5 (good, but less critical than blocking attacks)
    - False positive (blocked legitimate): -2.0 (very bad - hurts user experience)
    - False negative (allowed attack): -1.5 (bad - security risk)
    - High latency: -0.1 to -0.5 (penalty)
    - Used less restrictive action successfully: +0.2 (bonus for efficiency)
    """
    
    def __init__(
        self,
        attack_blocked_reward=1.0,
        legitimate_allowed_reward=0.5,
        false_positive_penalty=-2.0,
        false_negative_penalty=-1.5,
        latency_penalty_threshold_ms=1000,
        max_latency_penalty=-0.5,
        efficiency_bonus=0.2
    ):
        """Initialize reward calculator with configurable weights.
        
        Args:
            attack_blocked_reward: Reward for successfully blocking attack
            legitimate_allowed_reward: Reward for allowing legitimate request
            false_positive_penalty: Penalty for blocking legitimate request
            false_negative_penalty: Penalty for allowing attack
            latency_penalty_threshold_ms: Latency above which to apply penalty
            max_latency_penalty: Maximum penalty for high latency
            efficiency_bonus: Bonus for using less restrictive actions
        """
        self.attack_blocked_reward = attack_blocked_reward
        self.legitimate_allowed_reward = legitimate_allowed_reward
        self.false_positive_penalty = false_positive_penalty
        self.false_negative_penalty = false_negative_penalty
        self.latency_penalty_threshold_ms = latency_penalty_threshold_ms
        self.max_latency_penalty = max_latency_penalty
        self.efficiency_bonus = efficiency_bonus
    
    def calculate_reward(self, action, outcome):
        """Calculate reward based on action taken and observed outcome.
        
        Args:
            action: Action that was executed
            outcome: dict with keys:
                - 'is_attack': bool, whether request was actually an attack
                - 'http_status': int, HTTP response status code (optional)
                - 'latency_ms': float, request processing time (optional)
                - 'db_error': bool, whether database error occurred (optional)
                - 'user_complaint': bool, whether user reported issue (optional)
                
        Returns:
            float: Reward value (positive = good, negative = bad)
        """
        is_attack = outcome.get('is_attack', False)
        http_status = outcome.get('http_status', 200)
        latency_ms = outcome.get('latency_ms', 0)
        db_error = outcome.get('db_error', False)
        user_complaint = outcome.get('user_complaint', False)
        
        reward = 0.0
        
        # Base reward: correctness of decision
        if action in [Action.BLOCK, Action.CHALLENGE]:
            # Restrictive actions
            if is_attack:
                # Correctly blocked/challenged an attack
                reward += self.attack_blocked_reward
            else:
                # False positive - blocked legitimate request
                reward += self.false_positive_penalty
        
        elif action in [Action.ALLOW, Action.LOG_ONLY]:
            # Permissive actions
            if is_attack:
                # False negative - allowed an attack
                reward += self.false_negative_penalty
            else:
                # Correctly allowed legitimate request
                reward += self.legitimate_allowed_reward
        
        elif action == Action.SANITIZE:
            # Sanitize is a middle ground
            if is_attack:
                # Sanitized attack - partial success
                # Better than allowing, worse than blocking
                reward += self.attack_blocked_reward * 0.7
            else:
                # Sanitized legitimate request
                # Might have broken functionality, small penalty
                reward += self.legitimate_allowed_reward * 0.8
        
        elif action == Action.THROTTLE:
            # Throttle is defensive but allows request
            if is_attack:
                # Throttled attack - slowed them down but didn't stop
                reward += self.attack_blocked_reward * 0.5
            else:
                # Throttled legitimate user - annoying but not blocking
                reward += self.legitimate_allowed_reward * 0.6
        
        # Penalty for high latency
        if latency_ms > self.latency_penalty_threshold_ms:
            # Linear penalty based on how much over threshold
            excess_ms = latency_ms - self.latency_penalty_threshold_ms
            latency_penalty = min(
                0,
                self.max_latency_penalty * (excess_ms / self.latency_penalty_threshold_ms)
            )
            reward += latency_penalty
        
        # Penalty for database errors (might indicate SQL injection succeeded)
        if db_error:
            reward += -0.5
        
        # Strong penalty for user complaints (indicates false positive)
        if user_complaint:
            reward += -1.0
        
        # Bonus for efficiency: using less restrictive actions when safe
        if not is_attack and action in [Action.LOG_ONLY, Action.SANITIZE]:
            # Used monitoring/sanitization instead of blocking - good balance
            reward += self.efficiency_bonus
        
        # Penalty for HTTP errors (might indicate action broke the request)
        if http_status >= 500:
            reward += -0.3  # Server error
        elif http_status >= 400 and http_status != 403:
            # Client error (but not our intentional 403 block)
            reward += -0.1
        
        return reward
    
    def estimate_attack_probability(self, features):
        """Estimate if request is likely an attack based on features.
        
        This is a simple heuristic used when ground truth is not available.
        In production, you'd use labeled data or human review.
        
        Args:
            features: dict of extracted features
            
        Returns:
            float: Probability between 0 and 1 that request is an attack
        """
        score = 0.0
        
        # SQL injection indicators
        if features.get('sql_keyword_count', 0) > 0:
            score += 0.3
        
        if features.get('quote_count', 0) > 2:
            score += 0.2
        
        if features.get('comment_pattern_count', 0) > 0:
            score += 0.3
        
        if features.get('or_and_count', 0) > 0:
            score += 0.2
        
        # High entropy might indicate obfuscation
        if features.get('entropy', 0) > 5.0:
            score += 0.1
        
        # Multiple encoding layers
        if features.get('encoding_depth', 0) > 1:
            score += 0.2
        
        # Cap at 1.0
        return min(1.0, score)
    
    def calculate_reward_from_features(self, action, features, outcome):
        """Calculate reward when ground truth attack label is not available.
        
        Uses heuristic to estimate if request was an attack.
        
        Args:
            action: Action that was executed
            features: dict of extracted features
            outcome: dict with outcome info (without 'is_attack' field)
            
        Returns:
            float: Estimated reward
        """
        # Estimate attack probability
        attack_prob = self.estimate_attack_probability(features)
        
        # Use threshold to make binary decision
        is_attack = attack_prob > 0.5
        
        # Add estimated attack label to outcome
        outcome_with_label = outcome.copy()
        outcome_with_label['is_attack'] = is_attack
        outcome_with_label['attack_probability'] = attack_prob
        
        return self.calculate_reward(action, outcome_with_label)
    
    def get_reward_weights(self):
        """Get current reward weights for monitoring/tuning.
        
        Returns:
            dict: All reward weights
        """
        return {
            'attack_blocked_reward': self.attack_blocked_reward,
            'legitimate_allowed_reward': self.legitimate_allowed_reward,
            'false_positive_penalty': self.false_positive_penalty,
            'false_negative_penalty': self.false_negative_penalty,
            'latency_penalty_threshold_ms': self.latency_penalty_threshold_ms,
            'max_latency_penalty': self.max_latency_penalty,
            'efficiency_bonus': self.efficiency_bonus
        }
    
    def update_weights(self, **kwargs):
        """Update reward weights dynamically.
        
        Useful for tuning the system based on operational feedback.
        
        Args:
            **kwargs: Reward weight parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
