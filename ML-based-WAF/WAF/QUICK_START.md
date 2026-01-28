# Quick Start Guide: RL-based Adaptive WAF

## 🚀 Running the System

### Prerequisites
```bash
cd c:\Users\black\Desktop\db-guard\DB-guardian\ML-based-WAF\WAF
```

### Option 1: Passive Mode (Recommended First)
```bash
# Terminal 1: REST API
python rest_app.py

# Terminal 2: Dashboard
python dashboard.py

# Terminal 3: RL WAF (Passive - Safe Observation)
sudo python sniffing_rl.py --port 5000
```

### Option 2: Enforcement Mode (After Training)
```bash
# Same as above, but Terminal 3:
sudo python sniffing_rl.py --port 5000 --enforce
```

---

## 📊 What You'll See

### Console Output
```
[INFO] RL PASSIVE MODE - All actions forced to LOG_ONLY
[INFO] Starting RL-based WAF on port 5000
[INFO] Exploration rate: 0.1
============================================================
[REQ 1] GET /api/user | RL:allow → Safe:allow → Final:log_only | Reward:+0.50 | Attack:0.00
[REQ 2] GET /login?id=1' OR 1=1 | RL:block → Safe:block → Final:log_only | Reward:-1.50 | Attack:0.85
[INFO] Checkpoint saved after 100 requests
```

### Dashboard
- Visit: http://127.0.0.1:8050
- View request logs, threat statistics, and patterns

---

## 🧪 Testing the System

### Run Integration Test
```bash
python test_rl_integration.py
```

**Expected Output:**
```
✓ Feature extraction working
✓ RL agent making decisions
✓ Safety layer enforcing constraints
✓ Action executor handling all actions
✓ Reward calculator providing feedback
✓ Online learning updating Q-table
✓ Passive mode (LOG_ONLY) working
✓ Enforcement mode (BLOCK) working
```

### Send Test Requests
```bash
# Benign request
curl http://localhost:5000/api/user?id=123

# SQL injection attempt
curl "http://localhost:5000/api/user?id=1' OR '1'='1"

# UNION attack
curl "http://localhost:5000/api/data?q=test' UNION SELECT * FROM users--"
```

---

## 🎯 Key Configuration

### In sniffing_rl.py

```python
# MODE CONTROL
RL_ENFORCEMENT_ENABLED = False  # True = enforce actions, False = LOG_ONLY

# LEARNING PARAMETERS
RL_EPSILON = 0.1          # 10% exploration, 90% exploitation
RL_LEARNING_RATE = 0.05   # Conservative learning rate

# REWARD WEIGHTS
REWARD_ATTACK_BLOCKED = 1.0
PENALTY_FALSE_POSITIVE = -2.0
```

### Command Line Options
```bash
--port 5000           # Port to monitor
--enforce             # Enable enforcement mode
--epsilon 0.2         # Custom exploration rate
```

---

## 📈 Understanding the Pipeline

```
HTTP Request
    ↓
[1] Feature Extraction (15 features)
    ↓
[2] RL Decision (epsilon-greedy)
    ↓
[3] Safety Layer (constraints)
    ↓
[4] Mode Check (passive/enforce)
    ↓
[5] Action Execution
    ↓
[6] Reward Calculation
    ↓
[7] Online Learning (Q-table update)
    ↓
[8] Logging
```

---

## 🛡️ Actions Explained

| Action | Description | When Used |
|--------|-------------|-----------|
| **ALLOW** | Forward unchanged | Low-risk requests |
| **LOG_ONLY** | Forward + log | Passive mode default |
| **SANITIZE** | Remove SQL keywords | Medium-risk requests |
| **CHALLENGE** | Require CAPTCHA | Suspicious but uncertain |
| **THROTTLE** | Add 500ms delay | Rate limiting |
| **BLOCK** | Drop with 403 | High-confidence attacks |

---

## 🎓 Learning Process

### How the Agent Learns

1. **Initial State:** Random Q-values
2. **Exploration:** Try different actions (10% of time)
3. **Observation:** See what happens (reward)
4. **Update:** Adjust Q-values based on reward
5. **Exploitation:** Use learned policy (90% of time)

### Reward Signal

- ✅ **Blocked attack:** +1.0
- ✅ **Allowed legitimate:** +0.5
- ❌ **Blocked legitimate:** -2.0 (false positive)
- ❌ **Allowed attack:** -1.5 (false negative)

---

## 🔍 Monitoring

### Check Policy Statistics
```python
from rl_agent import PolicyAgent

agent = PolicyAgent()
agent.load_checkpoint('rl_policy_checkpoint.pkl')
stats = agent.get_statistics()

print(f"Total updates: {stats['total_updates']}")
print(f"States learned: {stats['q_table_size']}")
print(f"Exploration ratio: {stats['exploration_ratio']:.2%}")
```

### View Q-values
```python
# Get Q-value for specific state-action pair
state = {'sql_keyword_count': 2, 'quote_count': 4, ...}
action = Action.BLOCK
q_value = agent.get_q_value(state, action)
print(f"Q({state}, {action}) = {q_value}")
```

---

## ⚠️ Safety Features

### Passive Mode (Default)
- All actions → LOG_ONLY
- No user impact
- Safe for training

### Safety Layer
- Never BLOCK `/admin/*` endpoints
- Internal IPs → CHALLENGE (not BLOCK)
- Health checks → always ALLOW

### Fail Open
- If RL crashes → allow request
- Logs error for debugging
- Prioritizes availability

---

## 📝 Files Reference

### Core Modules
- `feature_extractor.py` - Extract 15 features
- `rl_agent.py` - Contextual bandit
- `safety_layer.py` - Hard constraints
- `action_executor.py` - Execute actions
- `reward_calculator.py` - Calculate rewards

### Integration
- `sniffing_rl.py` - **Main RL-based WAF**

### Tests
- `test_rl_integration.py` - End-to-end test
- `test_feature_extractor.py` - Feature tests
- `test_rl_agent.py` - Agent tests
- `test_safety_and_executor.py` - Safety tests
- `test_reward_calculator.py` - Reward tests

---

## 🚨 Troubleshooting

### "Permission denied" when running sniffing_rl.py
```bash
# Run with sudo (requires packet capture permissions)
sudo python sniffing_rl.py --port 5000
```

### No requests being captured
```bash
# Check if REST server is running on correct port
netstat -an | grep 5000

# Verify interface name (might not be 'lo')
# Edit sniffing_rl.py line: iface='lo' → iface='your_interface'
```

### Agent not learning
- Check reward values in logs
- Verify features are being extracted (not all zeros)
- Increase exploration rate: `--epsilon 0.3`

---

## 🎯 Deployment Checklist

- [ ] Test in passive mode for 1-2 weeks
- [ ] Collect 10,000+ requests
- [ ] Review false positive rate (<1%)
- [ ] Verify Q-table convergence
- [ ] Enable enforcement on non-critical endpoints first
- [ ] Monitor user complaints
- [ ] Keep rollback checkpoint ready

---

## 📚 Learn More

- **Walkthrough:** [walkthrough.md](file:///C:/Users/black/.gemini/antigravity/brain/9456efb3-58f0-4322-943b-cfba806ffd2c/walkthrough.md)
- **Implementation Plan:** [implementation_plan.md](file:///C:/Users/black/.gemini/antigravity/brain/9456efb3-58f0-4322-943b-cfba806ffd2c/implementation_plan.md)
- **Task Progress:** [task.md](file:///C:/Users/black/.gemini/antigravity/brain/9456efb3-58f0-4322-943b-cfba806ffd2c/task.md)
