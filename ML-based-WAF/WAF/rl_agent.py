'''Reinforcement Learning decision engine for adaptive WAF.

This module implements a lightweight contextual bandit algorithm for policy-based
request handling. It replaces static ML classification with online learning that
adapts based on real outcomes.

Algorithm: Epsilon-greedy contextual bandit
- Exploration: randomly try actions to discover better policies
- Exploitation: choose actions with highest expected reward
- No deep learning required - uses tabular Q-learning
'''

from enum import Enum
import random
from collections import defaultdict
import pickle
import os


class Action(Enum):
    """Actions the WAF can take on a request."""
    ALLOW = 'allow'           # Forward request unchanged
    LOG_ONLY = 'log_only'     # Forward but log for analysis
    SANITIZE = 'sanitize'     # Clean SQL tokens before forwarding
    CHALLENGE = 'challenge'   # Require CAPTCHA or re-authentication
    THROTTLE = 'throttle'     # Rate limit or add delay
    BLOCK = 'block'           # Drop request with 403


class PolicyAgent:
    """RL agent that learns optimal actions for each request state.
    
    Uses contextual bandit with epsilon-greedy exploration:
    - Maintains Q-values Q(state, action) = expected reward
    - Explores with probability epsilon (try random actions)
    - Exploits with probability 1-epsilon (choose best known action)
    - Updates Q-values incrementally using observed rewards
    
    This is simpler than full Q-learning because we don't model state transitions.
    Each request is treated independently (bandit assumption).
    """
    
    def __init__(self, epsilon=0.1, learning_rate=0.1, default_q_value=0.0):
        """Initialize the policy agent.
        
        Args:
            epsilon: Exploration rate (0.0 = pure exploitation, 1.0 = pure exploration)
            learning_rate: How quickly to update Q-values (0.0 = no learning, 1.0 = immediate)
            default_q_value: Initial Q-value for unseen (state, action) pairs
        """
        # Q-table: maps (state, action) -> expected reward
        # Using defaultdict so unseen states get default_q_value
        self.q_table = defaultdict(lambda: default_q_value)
        
        # Hyperparameters
        self.epsilon = epsilon
        self.learning_rate = learning_rate
        self.default_q_value = default_q_value
        
        # Statistics for monitoring
        self.total_updates = 0
        self.exploration_count = 0
        self.exploitation_count = 0
    
    def _state_to_key(self, state):
        """Convert state (feature dict) to hashable key for Q-table.
        
        Args:
            state: dict of features (e.g., {'sql_keyword_count': 5, 'quote_count': 2})
            
        Returns:
            tuple: Hashable representation of state
        """
        # Sort by key to ensure consistent ordering
        # Round floats to avoid precision issues
        items = []
        for key in sorted(state.keys()):
            value = state[key]
            if isinstance(value, float):
                value = round(value, 4)
            items.append((key, value))
        return tuple(items)
    
    def select_action(self, state):
        """Select action using epsilon-greedy policy.
        
        Args:
            state: dict of features extracted from request
            
        Returns:
            Action: Selected action
        """
        state_key = self._state_to_key(state)
        
        # Epsilon-greedy: explore with probability epsilon
        if random.random() < self.epsilon:
            # EXPLORATION: try a random action to discover better policies
            action = random.choice(list(Action))
            self.exploration_count += 1
        else:
            # EXPLOITATION: choose action with highest Q-value
            action = self._get_best_action(state_key)
            self.exploitation_count += 1
        
        return action
    
    def _get_best_action(self, state_key):
        """Get action with highest Q-value for given state.
        
        Args:
            state_key: Hashable state representation
            
        Returns:
            Action: Action with max Q-value
        """
        # Get Q-values for all actions in this state
        q_values = {}
        for action in Action:
            q_values[action] = self.q_table[(state_key, action)]
        
        # Return action with highest Q-value
        # If multiple actions have same Q-value, random.choice breaks tie
        max_q = max(q_values.values())
        best_actions = [a for a, q in q_values.items() if q == max_q]
        return random.choice(best_actions)
    
    def update(self, state, action, reward):
        """Update Q-value based on observed reward (online learning).
        
        Uses incremental update rule:
        Q(s,a) ← Q(s,a) + α * (reward - Q(s,a))
        
        Where α is the learning rate. This gradually shifts Q-value toward
        observed rewards while maintaining stability.
        
        Args:
            state: dict of features from the request
            action: Action that was taken
            reward: Observed reward (positive = good, negative = bad)
        """
        state_key = self._state_to_key(state)
        key = (state_key, action)
        
        # Current Q-value estimate
        old_q = self.q_table[key]
        
        # Incremental update: move Q-value toward observed reward
        # learning_rate controls how much we trust new vs old information
        new_q = old_q + self.learning_rate * (reward - old_q)
        
        # Update Q-table
        self.q_table[key] = new_q
        
        self.total_updates += 1
    
    def get_q_values(self, state):
        """Get Q-values for all actions in given state (for debugging/monitoring).
        
        Args:
            state: dict of features
            
        Returns:
            dict: Maps Action -> Q-value
        """
        state_key = self._state_to_key(state)
        q_values = {}
        for action in Action:
            q_values[action] = self.q_table[(state_key, action)]
        return q_values
    
    def get_statistics(self):
        """Get agent statistics for monitoring.
        
        Returns:
            dict: Statistics about agent behavior
        """
        total_decisions = self.exploration_count + self.exploitation_count
        exploration_ratio = (
            self.exploration_count / total_decisions 
            if total_decisions > 0 else 0.0
        )
        
        return {
            'total_updates': self.total_updates,
            'total_decisions': total_decisions,
            'exploration_count': self.exploration_count,
            'exploitation_count': self.exploitation_count,
            'exploration_ratio': exploration_ratio,
            'q_table_size': len(self.q_table),
            'epsilon': self.epsilon,
            'learning_rate': self.learning_rate
        }
    
    def save_checkpoint(self, filepath='policy_checkpoint.pkl'):
        """Save Q-table and hyperparameters to disk.
        
        Args:
            filepath: Path to save checkpoint
        """
        checkpoint = {
            'q_table': dict(self.q_table),  # Convert defaultdict to dict
            'epsilon': self.epsilon,
            'learning_rate': self.learning_rate,
            'default_q_value': self.default_q_value,
            'total_updates': self.total_updates,
            'exploration_count': self.exploration_count,
            'exploitation_count': self.exploitation_count
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(checkpoint, f)
    
    def load_checkpoint(self, filepath='policy_checkpoint.pkl'):
        """Load Q-table and hyperparameters from disk.
        
        Args:
            filepath: Path to checkpoint file
            
        Returns:
            bool: True if loaded successfully, False if file not found
        """
        if not os.path.exists(filepath):
            return False
        
        with open(filepath, 'rb') as f:
            checkpoint = pickle.load(f)
        
        # Restore Q-table as defaultdict
        self.q_table = defaultdict(
            lambda: checkpoint['default_q_value'],
            checkpoint['q_table']
        )
        
        # Restore hyperparameters and statistics
        self.epsilon = checkpoint['epsilon']
        self.learning_rate = checkpoint['learning_rate']
        self.default_q_value = checkpoint['default_q_value']
        self.total_updates = checkpoint['total_updates']
        self.exploration_count = checkpoint['exploration_count']
        self.exploitation_count = checkpoint['exploitation_count']
        
        return True
    
    def set_epsilon(self, epsilon):
        """Adjust exploration rate (useful for reducing exploration over time).
        
        Args:
            epsilon: New exploration rate (0.0 to 1.0)
        """
        self.epsilon = max(0.0, min(1.0, epsilon))
    
    def reset_statistics(self):
        """Reset decision counters (useful after loading checkpoint)."""
        self.total_updates = 0
        self.exploration_count = 0
        self.exploitation_count = 0
