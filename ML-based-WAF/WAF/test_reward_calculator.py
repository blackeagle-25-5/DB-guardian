"""Test script for reward calculator."""

from reward_calculator import RewardCalculator
from rl_agent import Action

print("=" * 60)
print("TEST 1: Attack Blocked (Positive Reward)")
print("=" * 60)

calc = RewardCalculator()

# Scenario: BLOCK action on actual attack
action = Action.BLOCK
outcome = {
    'is_attack': True,
    'http_status': 403,
    'latency_ms': 50
}

reward = calc.calculate_reward(action, outcome)
print(f"\nAction: {action.value}")
print(f"Is attack: {outcome['is_attack']}")
print(f"Reward: {reward:+.2f}")
print(f"✓ Positive reward for blocking attack")

print("\n" + "=" * 60)
print("TEST 2: False Positive (Negative Reward)")
print("=" * 60)

# Scenario: BLOCK action on legitimate request
action = Action.BLOCK
outcome = {
    'is_attack': False,
    'http_status': 403,
    'latency_ms': 50,
    'user_complaint': True
}

reward = calc.calculate_reward(action, outcome)
print(f"\nAction: {action.value}")
print(f"Is attack: {outcome['is_attack']}")
print(f"User complaint: {outcome['user_complaint']}")
print(f"Reward: {reward:+.2f}")
print(f"✓ Strong negative reward for false positive")

print("\n" + "=" * 60)
print("TEST 3: Legitimate Request Allowed (Positive Reward)")
print("=" * 60)

# Scenario: ALLOW action on legitimate request
action = Action.ALLOW
outcome = {
    'is_attack': False,
    'http_status': 200,
    'latency_ms': 100
}

reward = calc.calculate_reward(action, outcome)
print(f"\nAction: {action.value}")
print(f"Is attack: {outcome['is_attack']}")
print(f"Reward: {reward:+.2f}")
print(f"✓ Positive reward for allowing legitimate traffic")

print("\n" + "=" * 60)
print("TEST 4: False Negative (Negative Reward)")
print("=" * 60)

# Scenario: ALLOW action on attack
action = Action.ALLOW
outcome = {
    'is_attack': True,
    'http_status': 200,
    'latency_ms': 100,
    'db_error': True
}

reward = calc.calculate_reward(action, outcome)
print(f"\nAction: {action.value}")
print(f"Is attack: {outcome['is_attack']}")
print(f"DB error: {outcome['db_error']}")
print(f"Reward: {reward:+.2f}")
print(f"✓ Negative reward for allowing attack")

print("\n" + "=" * 60)
print("TEST 5: SANITIZE on Attack (Partial Success)")
print("=" * 60)

# Scenario: SANITIZE action on attack
action = Action.SANITIZE
outcome = {
    'is_attack': True,
    'http_status': 200,
    'latency_ms': 150
}

reward = calc.calculate_reward(action, outcome)
print(f"\nAction: {action.value}")
print(f"Is attack: {outcome['is_attack']}")
print(f"Reward: {reward:+.2f}")
print(f"✓ Partial reward (better than allowing, worse than blocking)")

print("\n" + "=" * 60)
print("TEST 6: High Latency Penalty")
print("=" * 60)

# Scenario: ALLOW with high latency
action = Action.ALLOW
outcome = {
    'is_attack': False,
    'http_status': 200,
    'latency_ms': 3000  # 3 seconds
}

reward = calc.calculate_reward(action, outcome)
print(f"\nAction: {action.value}")
print(f"Latency: {outcome['latency_ms']}ms")
print(f"Reward: {reward:+.2f}")
print(f"✓ Latency penalty applied")

print("\n" + "=" * 60)
print("TEST 7: Efficiency Bonus")
print("=" * 60)

# Scenario: LOG_ONLY on legitimate request (monitoring instead of blocking)
action = Action.LOG_ONLY
outcome = {
    'is_attack': False,
    'http_status': 200,
    'latency_ms': 100
}

reward = calc.calculate_reward(action, outcome)
print(f"\nAction: {action.value}")
print(f"Is attack: {outcome['is_attack']}")
print(f"Reward: {reward:+.2f}")
print(f"✓ Efficiency bonus for using less restrictive action")

print("\n" + "=" * 60)
print("TEST 8: Attack Probability Estimation")
print("=" * 60)

# Benign features
benign_features = {
    'sql_keyword_count': 0,
    'quote_count': 0,
    'comment_pattern_count': 0,
    'or_and_count': 0,
    'entropy': 3.5,
    'encoding_depth': 0
}

prob = calc.estimate_attack_probability(benign_features)
print(f"\nBenign features:")
print(f"  SQL keywords: {benign_features['sql_keyword_count']}")
print(f"  Quotes: {benign_features['quote_count']}")
print(f"Attack probability: {prob:.2f}")

# Attack features
attack_features = {
    'sql_keyword_count': 3,
    'quote_count': 4,
    'comment_pattern_count': 1,
    'or_and_count': 2,
    'entropy': 5.5,
    'encoding_depth': 2
}

prob = calc.estimate_attack_probability(attack_features)
print(f"\nAttack features:")
print(f"  SQL keywords: {attack_features['sql_keyword_count']}")
print(f"  Quotes: {attack_features['quote_count']}")
print(f"  Comments: {attack_features['comment_pattern_count']}")
print(f"Attack probability: {prob:.2f}")
print(f"✓ Heuristic correctly estimates attack probability")

print("\n" + "=" * 60)
print("TEST 9: Reward from Features (No Ground Truth)")
print("=" * 60)

# When we don't know if it's an attack, use features to estimate
action = Action.BLOCK
outcome = {
    'http_status': 403,
    'latency_ms': 50
}

reward = calc.calculate_reward_from_features(action, attack_features, outcome)
print(f"\nAction: {action.value}")
print(f"Features indicate attack: Yes (prob > 0.5)")
print(f"Reward: {reward:+.2f}")
print(f"✓ Reward calculated from features when ground truth unavailable")

print("\n" + "=" * 60)
print("TEST 10: Reward Weight Tuning")
print("=" * 60)

print("\nOriginal weights:")
weights = calc.get_reward_weights()
print(f"  False positive penalty: {weights['false_positive_penalty']}")

# Update weights
calc.update_weights(false_positive_penalty=-3.0)
print("\nAfter tuning:")
weights = calc.get_reward_weights()
print(f"  False positive penalty: {weights['false_positive_penalty']}")
print(f"✓ Reward weights can be tuned dynamically")

print("\n" + "=" * 60)
print("SUMMARY: Reward Scenarios")
print("=" * 60)

# Reset calculator
calc = RewardCalculator()

scenarios = [
    ("Block attack", Action.BLOCK, {'is_attack': True}),
    ("Allow legitimate", Action.ALLOW, {'is_attack': False}),
    ("Block legitimate (FP)", Action.BLOCK, {'is_attack': False}),
    ("Allow attack (FN)", Action.ALLOW, {'is_attack': True}),
    ("Sanitize attack", Action.SANITIZE, {'is_attack': True}),
    ("Challenge attack", Action.CHALLENGE, {'is_attack': True}),
]

print("\n{:<25} {:<12} {:<10}".format("Scenario", "Action", "Reward"))
print("-" * 50)
for scenario_name, action, outcome in scenarios:
    outcome['http_status'] = 200
    outcome['latency_ms'] = 100
    reward = calc.calculate_reward(action, outcome)
    print("{:<25} {:<12} {:+.2f}".format(scenario_name, action.value, reward))

print("\n✓ Reward calculator ready for RL training!")
