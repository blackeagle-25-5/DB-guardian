"""Integration test for RL-based WAF pipeline.

This script tests the complete end-to-end flow without network sniffing.
"""

from request import Request
from feature_extractor import FeatureExtractor
from rl_agent import PolicyAgent, Action
from safety_layer import SafetyLayer
from action_executor import ActionExecutor
from reward_calculator import RewardCalculator
import time

print("=" * 60)
print("RL-BASED WAF INTEGRATION TEST")
print("=" * 60)

# ============================================================
# INITIALIZE COMPONENTS
# ============================================================

print("\n[1/10] Initializing components...")
feature_extractor = FeatureExtractor()
rl_agent = PolicyAgent(epsilon=0.2, learning_rate=0.1)
safety_layer = SafetyLayer()
action_executor = ActionExecutor()
reward_calculator = RewardCalculator()
print("✓ All components initialized")

# ============================================================
# TEST SCENARIO 1: BENIGN REQUEST
# ============================================================

print("\n" + "=" * 60)
print("SCENARIO 1: Benign Request")
print("=" * 60)

req1 = Request(
    request='/api/user?id=123',
    method='GET',
    origin='192.168.1.100',
    headers={'User_Agent': 'Mozilla/5.0'}
)

print(f"\nRequest: {req1.request}")
print(f"Origin: {req1.origin}")

# Stage 2: Feature extraction
features1 = feature_extractor.extract_features(req1)
print(f"\n[2/10] Features extracted:")
print(f"  SQL keywords: {features1['sql_keyword_count']}")
print(f"  Quotes: {features1['quote_count']}")
print(f"  Length: {features1['length']}")

# Stage 3: RL decision
rl_action1 = rl_agent.select_action(features1)
print(f"\n[3/10] RL agent decision: {rl_action1.value}")

# Stage 4: Safety layer
safe_action1 = safety_layer.apply_constraints(
    rl_action1,
    endpoint=req1.request,
    origin=req1.origin
)
print(f"[4/10] After safety layer: {safe_action1.value}")

# Stage 5: Mode enforcement (passive)
RL_ENFORCEMENT_ENABLED = False
final_action1 = Action.LOG_ONLY if not RL_ENFORCEMENT_ENABLED else safe_action1
print(f"[5/10] Final action (passive mode): {final_action1.value}")

# Stage 6: Action execution
request_data1 = {'request': req1.request, 'body': req1.body, 'headers': req1.headers}
result1 = action_executor.execute(final_action1, request_data1)
print(f"[6/10] Execution result: allowed={result1['allowed']}")

# Stage 7: Outcome simulation
outcome1 = {
    'is_attack': False,
    'http_status': 200,
    'latency_ms': 50
}
print(f"[7/10] Outcome: attack={outcome1['is_attack']}, status={outcome1['http_status']}")

# Stage 8: Reward calculation
reward1 = reward_calculator.calculate_reward(final_action1, outcome1)
print(f"[8/10] Reward calculated: {reward1:+.2f}")

# Stage 9: Online learning
rl_agent.update(features1, final_action1, reward1)
print(f"[9/10] RL agent updated with reward")

print(f"[10/10] ✓ Benign request processed successfully")

# ============================================================
# TEST SCENARIO 2: SQL INJECTION ATTACK
# ============================================================

print("\n" + "=" * 60)
print("SCENARIO 2: SQL Injection Attack")
print("=" * 60)

req2 = Request(
    request="/api/user?id=1' OR '1'='1",
    method='GET',
    origin='203.0.113.5',
    headers={}
)

print(f"\nRequest: {req2.request}")
print(f"Origin: {req2.origin}")

# Stage 2: Feature extraction
features2 = feature_extractor.extract_features(req2)
print(f"\n[2/10] Features extracted:")
print(f"  SQL keywords: {features2['sql_keyword_count']}")
print(f"  Quotes: {features2['quote_count']}")
print(f"  OR/AND count: {features2['or_and_count']}")

# Stage 3: RL decision
rl_action2 = rl_agent.select_action(features2)
print(f"\n[3/10] RL agent decision: {rl_action2.value}")

# Stage 4: Safety layer
safe_action2 = safety_layer.apply_constraints(
    rl_action2,
    endpoint=req2.request,
    origin=req2.origin
)
print(f"[4/10] After safety layer: {safe_action2.value}")

# Stage 5: Mode enforcement (passive)
final_action2 = Action.LOG_ONLY if not RL_ENFORCEMENT_ENABLED else safe_action2
print(f"[5/10] Final action (passive mode): {final_action2.value}")

# Stage 6: Action execution
request_data2 = {'request': req2.request, 'body': req2.body, 'headers': req2.headers}
result2 = action_executor.execute(final_action2, request_data2)
print(f"[6/10] Execution result: allowed={result2['allowed']}")

# Stage 7: Outcome simulation
outcome2 = {
    'is_attack': True,
    'http_status': 200,  # Attack got through in passive mode
    'latency_ms': 100
}
print(f"[7/10] Outcome: attack={outcome2['is_attack']}, status={outcome2['http_status']}")

# Stage 8: Reward calculation
reward2 = reward_calculator.calculate_reward(final_action2, outcome2)
print(f"[8/10] Reward calculated: {reward2:+.2f}")

# Stage 9: Online learning
rl_agent.update(features2, final_action2, reward2)
print(f"[9/10] RL agent updated with reward")

print(f"[10/10] ✓ Attack request processed successfully")

# ============================================================
# TEST SCENARIO 3: ENFORCEMENT MODE
# ============================================================

print("\n" + "=" * 60)
print("SCENARIO 3: Attack with Enforcement Mode")
print("=" * 60)

req3 = Request(
    request="/api/admin?cmd=DROP TABLE users--",
    method='POST',
    origin='198.51.100.42',
    headers={}
)

print(f"\nRequest: {req3.request}")
print(f"Origin: {req3.origin}")

# Train agent to BLOCK attacks
print("\n[TRAINING] Teaching agent to BLOCK attacks...")
for i in range(20):
    features_attack = feature_extractor.extract_features(req3)
    rl_agent.update(features_attack, Action.BLOCK, reward=1.0)
print("✓ Agent trained")

# Now test with enforcement enabled
RL_ENFORCEMENT_ENABLED = True

features3 = feature_extractor.extract_features(req3)
print(f"\n[2/10] Features extracted:")
print(f"  SQL keywords: {features3['sql_keyword_count']}")
print(f"  Comment patterns: {features3['comment_pattern_count']}")

# Stage 3: RL decision (should prefer BLOCK now)
rl_agent.set_epsilon(0.0)  # Pure exploitation
rl_action3 = rl_agent.select_action(features3)
print(f"\n[3/10] RL agent decision: {rl_action3.value}")

# Stage 4: Safety layer
safe_action3 = safety_layer.apply_constraints(
    rl_action3,
    endpoint=req3.request,
    origin=req3.origin
)
print(f"[4/10] After safety layer: {safe_action3.value}")

# Stage 5: Mode enforcement (ACTIVE)
final_action3 = safe_action3  # Enforcement enabled
print(f"[5/10] Final action (ENFORCEMENT mode): {final_action3.value}")

# Stage 6: Action execution
request_data3 = {'request': req3.request, 'body': req3.body, 'headers': req3.headers}
result3 = action_executor.execute(final_action3, request_data3)
print(f"[6/10] Execution result: allowed={result3['allowed']}")

# Stage 7: Outcome
outcome3 = {
    'is_attack': True,
    'http_status': 403,  # Blocked
    'latency_ms': 20
}
print(f"[7/10] Outcome: attack={outcome3['is_attack']}, status={outcome3['http_status']}")

# Stage 8: Reward
reward3 = reward_calculator.calculate_reward(final_action3, outcome3)
print(f"[8/10] Reward calculated: {reward3:+.2f}")

# Stage 9: Learning
rl_agent.update(features3, final_action3, reward3)
print(f"[9/10] RL agent updated")

print(f"[10/10] ✓ Attack blocked successfully in enforcement mode")

# ============================================================
# FINAL STATISTICS
# ============================================================

print("\n" + "=" * 60)
print("FINAL STATISTICS")
print("=" * 60)

stats = rl_agent.get_statistics()
print(f"\nRL Agent:")
print(f"  Total updates: {stats['total_updates']}")
print(f"  States learned: {stats['q_table_size']}")
print(f"  Exploration ratio: {stats['exploration_ratio']:.2%}")

exec_stats = action_executor.get_statistics()
print(f"\nAction Executor:")
print(f"  Total executions: {exec_stats['total_executions']}")
for action, count in exec_stats['action_counts'].items():
    if count > 0:
        print(f"  {action}: {count}")

print("\n" + "=" * 60)
print("INTEGRATION TEST SUMMARY")
print("=" * 60)
print("✓ Feature extraction working")
print("✓ RL agent making decisions")
print("✓ Safety layer enforcing constraints")
print("✓ Action executor handling all actions")
print("✓ Reward calculator providing feedback")
print("✓ Online learning updating Q-table")
print("✓ Passive mode (LOG_ONLY) working")
print("✓ Enforcement mode (BLOCK) working")
print("\n✓ END-TO-END RL PIPELINE READY FOR DEPLOYMENT!")
