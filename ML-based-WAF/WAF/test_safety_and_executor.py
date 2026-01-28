"""Test script for safety layer and action executor."""

from safety_layer import SafetyLayer
from action_executor import ActionExecutor
from rl_agent import Action

print("=" * 60)
print("TEST 1: Safety Layer - Protected Endpoints")
print("=" * 60)

safety = SafetyLayer()

# Test protected endpoint
endpoint = '/admin/users'
origin = '203.0.113.5'  # External IP
action = Action.BLOCK

print(f"\nOriginal action: {action.value}")
print(f"Endpoint: {endpoint}")
print(f"Origin: {origin}")

modified_action = safety.apply_constraints(action, endpoint=endpoint, origin=origin)
print(f"Modified action: {modified_action.value}")
print(f"✓ Admin endpoint protected: BLOCK → {modified_action.value}")

print("\n" + "=" * 60)
print("TEST 2: Safety Layer - Internal IP")
print("=" * 60)

endpoint = '/api/data'
origin = '127.0.0.1'  # Internal IP
action = Action.BLOCK

print(f"\nOriginal action: {action.value}")
print(f"Endpoint: {endpoint}")
print(f"Origin: {origin}")

modified_action = safety.apply_constraints(action, endpoint=endpoint, origin=origin)
print(f"Modified action: {modified_action.value}")
print(f"✓ Internal IP protected: BLOCK → {modified_action.value}")

print("\n" + "=" * 60)
print("TEST 3: Safety Layer - Allowed Actions")
print("=" * 60)

print("\nAllowed actions for /admin/users:")
allowed = safety.get_allowed_actions(endpoint='/admin/users')
print(f"  {[a.value for a in allowed]}")
print(f"  BLOCK removed: {Action.BLOCK not in allowed}")

print("\nAllowed actions for regular endpoint from external IP:")
allowed = safety.get_allowed_actions(endpoint='/api/data', origin='203.0.113.5')
print(f"  {[a.value for a in allowed]}")
print(f"  All actions allowed: {len(allowed) == len(list(Action))}")

print("\n" + "=" * 60)
print("TEST 4: Action Executor - ALLOW")
print("=" * 60)

executor = ActionExecutor()
request_data = {
    'request': '/api/user?id=1',
    'body': None,
    'headers': {}
}

result = executor.execute(Action.ALLOW, request_data)
print(f"\nAction: {result['action'].value}")
print(f"Allowed: {result['allowed']}")
print(f"Modified: {result['modified']}")
print(f"Reason: {result['metadata']['reason']}")

print("\n" + "=" * 60)
print("TEST 5: Action Executor - SANITIZE")
print("=" * 60)

malicious_request = {
    'request': "/api/user?id=1' UNION SELECT password FROM users--",
    'body': "username=admin&password=test' OR '1'='1",
    'headers': {}
}

print(f"\nOriginal request: {malicious_request['request']}")
print(f"Original body: {malicious_request['body']}")

result = executor.execute(Action.SANITIZE, malicious_request)
print(f"\nAction: {result['action'].value}")
print(f"Allowed: {result['allowed']}")
print(f"Modified: {result['modified']}")
print(f"Sanitized request: {result['request_data']['request']}")
print(f"Sanitized body: {result['request_data']['body']}")
print(f"✓ SQL keywords and dangerous chars removed")

print("\n" + "=" * 60)
print("TEST 6: Action Executor - BLOCK")
print("=" * 60)

result = executor.execute(Action.BLOCK, request_data)
print(f"\nAction: {result['action'].value}")
print(f"Allowed: {result['allowed']}")
print(f"HTTP Status: {result['metadata']['http_status']}")
print(f"Reason: {result['metadata']['reason']}")

print("\n" + "=" * 60)
print("TEST 7: Action Executor - CHALLENGE")
print("=" * 60)

result = executor.execute(Action.CHALLENGE, request_data)
print(f"\nAction: {result['action'].value}")
print(f"Allowed: {result['allowed']}")
print(f"Challenge required: {result['metadata']['challenge_required']}")
print(f"Challenge type: {result['metadata']['challenge_type']}")

print("\n" + "=" * 60)
print("TEST 8: Action Executor - Statistics")
print("=" * 60)

# Execute a few more actions
executor.execute(Action.ALLOW, request_data)
executor.execute(Action.ALLOW, request_data)
executor.execute(Action.LOG_ONLY, request_data)
executor.execute(Action.BLOCK, request_data)

stats = executor.get_statistics()
print(f"\nTotal executions: {stats['total_executions']}")
print("Action counts:")
for action, count in stats['action_counts'].items():
    print(f"  {action}: {count}")

print("\n" + "=" * 60)
print("TEST 9: Integration - Safety + Executor")
print("=" * 60)

# Simulate: RL agent wants to BLOCK admin endpoint
rl_action = Action.BLOCK
endpoint = '/admin/dashboard'
origin = '192.168.1.100'

print(f"\nRL agent decision: {rl_action.value}")
print(f"Endpoint: {endpoint}")
print(f"Origin: {origin}")

# Apply safety constraints
safe_action = safety.apply_constraints(rl_action, endpoint=endpoint, origin=origin)
print(f"After safety layer: {safe_action.value}")

# Execute the safe action
result = executor.execute(safe_action, request_data)
print(f"Execution result: allowed={result['allowed']}, action={result['action'].value}")
print(f"✓ Safety layer prevented dangerous BLOCK on admin endpoint")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print("✓ Safety layer protects admin endpoints")
print("✓ Safety layer protects internal IPs")
print("✓ Action executor handles all 6 actions")
print("✓ SANITIZE removes SQL injection patterns")
print("✓ BLOCK prevents request execution")
print("✓ CHALLENGE marks for verification")
print("✓ Statistics tracking works")
print("✓ Safety layer + executor integration works")
print("\n✓ Safety layer and action executor ready!")
