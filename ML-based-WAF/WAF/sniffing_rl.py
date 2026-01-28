'''RL-based adaptive WAF with end-to-end request processing pipeline.

This module implements the complete RL-based SQL injection prevention system:
1. HTTP request ingress
2. Feature extraction
3. RL policy decision
4. Safety layer enforcement
5. Action execution
6. Response capture
7. Reward calculation
8. Online learning update
9. Comprehensive logging

Two operational modes:
- MODE A (PASSIVE): All actions forced to LOG_ONLY for safe observation
- MODE B (ENFORCEMENT): RL actions are enforced after safety layer
'''

from scapy.all import sniff, Raw
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
import urllib.parse
import time
import traceback
from argparse import ArgumentParser

# Import existing modules
from request import Request, DBController

# Import RL modules
from feature_extractor import FeatureExtractor
from rl_agent import PolicyAgent, Action
from safety_layer import SafetyLayer
from action_executor import ActionExecutor
from reward_calculator import RewardCalculator

# ============================================================
# CONFIGURATION
# ============================================================

# MODE A (PASSIVE): Safe observation mode - all actions become LOG_ONLY
# MODE B (ENFORCEMENT): RL actions are enforced (use with caution)
RL_ENFORCEMENT_ENABLED = False  # Default: PASSIVE mode for safety

# RL Agent Configuration
RL_EPSILON = 0.1  # Exploration rate (10% random actions)
RL_LEARNING_RATE = 0.05  # Conservative learning rate
RL_CHECKPOINT_FILE = 'rl_policy_checkpoint.pkl'

# Reward Configuration
REWARD_ATTACK_BLOCKED = 1.0
REWARD_LEGITIMATE_ALLOWED = 0.5
PENALTY_FALSE_POSITIVE = -2.0
PENALTY_FALSE_NEGATIVE = -1.5

# ============================================================
# COMMAND LINE ARGUMENTS
# ============================================================

parser = ArgumentParser()
parser.add_argument('--port', type=int, default=5000, 
                    help='Port to monitor for HTTP traffic')
parser.add_argument('--enforce', action='store_true',
                    help='Enable RL enforcement mode (default: passive/LOG_ONLY)')
parser.add_argument('--epsilon', type=float, default=RL_EPSILON,
                    help='RL exploration rate (0.0-1.0)')
args = parser.parse_args()

# Override enforcement mode from command line
if args.enforce:
    RL_ENFORCEMENT_ENABLED = True
    print("[WARNING] RL ENFORCEMENT MODE ENABLED - Actions will be executed")
else:
    print("[INFO] RL PASSIVE MODE - All actions forced to LOG_ONLY for observation")

# ============================================================
# INITIALIZE COMPONENTS
# ============================================================

# Scapy configuration
scapy.packet.bind_layers(TCP, HTTP, dport=args.port)
scapy.packet.bind_layers(TCP, HTTP, sport=args.port)

# Database controller
db = DBController()

# RL Pipeline Components
feature_extractor = FeatureExtractor()
rl_agent = PolicyAgent(epsilon=args.epsilon, learning_rate=RL_LEARNING_RATE)
safety_layer = SafetyLayer()
action_executor = ActionExecutor(throttle_delay_ms=500)
reward_calculator = RewardCalculator(
    attack_blocked_reward=REWARD_ATTACK_BLOCKED,
    legitimate_allowed_reward=REWARD_LEGITIMATE_ALLOWED,
    false_positive_penalty=PENALTY_FALSE_POSITIVE,
    false_negative_penalty=PENALTY_FALSE_NEGATIVE
)

# Load existing policy if available
if rl_agent.load_checkpoint(RL_CHECKPOINT_FILE):
    print(f"[INFO] Loaded RL policy from {RL_CHECKPOINT_FILE}")
    stats = rl_agent.get_statistics()
    print(f"[INFO] Policy stats: {stats['total_updates']} updates, "
          f"{stats['q_table_size']} states learned")
else:
    print(f"[INFO] Starting with fresh RL policy")

# Statistics
request_count = 0
checkpoint_interval = 100  # Save policy every N requests

# ============================================================
# HTTP HEADER EXTRACTION
# ============================================================

header_fields = ['Http_Version', 'A_IM', 'Accept', 'Accept_Charset',
'Accept_Datetime', 'Accept_Encoding', 'Accept_Language',
'Access_Control_Request_Headers', 'Access_Control_Request_Method',
'Authorization', 'Cache_Control', 'Connection', 'Content_Length',
'Content_MD5', 'Content_Type', 'Cookie', 'DNT', 'Date', 'Expect',
'Forwarded', 'From', 'Front_End_Https', 'If_Match', 'If_Modified_Since',
'If_None_Match', 'If_Range', 'If_Unmodified_Since', 'Keep_Alive',
'Max_Forwards', 'Origin', 'Permanent', 'Pragma', 'Proxy_Authorization',
'Proxy_Connection', 'Range', 'Referer', 'Save_Data', 'TE', 'Upgrade',
'Upgrade_Insecure_Requests', 'User_Agent', 'Via', 'Warning',
'X_ATT_DeviceId', 'X_Correlation_ID', 'X_Csrf_Token', 'X_Forwarded_For',
'X_Forwarded_Host', 'X_Forwarded_Proto', 'X_Http_Method_Override',
'X_Request_ID', 'X_Requested_With', 'X_UIDH', 'X_Wap_Profile']

def get_header(packet):
    """Extract HTTP headers from packet."""
    headers = {}
    for field in header_fields:
        f = getattr(packet[HTTPRequest], field)
        if f != None and f != 'None':
            headers[field] = f.decode()
    return headers

# ============================================================
# MAIN REQUEST PROCESSING PIPELINE
# ============================================================

def process_request_with_rl(packet):
    """
    End-to-end RL-based request processing pipeline.
    
    Pipeline stages:
    1. HTTP request ingress
    2. Feature extraction
    3. RL policy decision
    4. Safety layer enforcement
    5. Action execution (or LOG_ONLY in passive mode)
    6. Response simulation (in real deployment, capture actual response)
    7. Reward calculation
    8. Online learning update
    9. Logging
    """
    global request_count
    
    if not packet.haslayer(HTTPRequest):
        return
    
    # Track request timing
    start_time = time.time()
    
    try:
        # ========================================================
        # STAGE 1: HTTP REQUEST INGRESS
        # ========================================================
        req = Request()
        
        # Extract origin IP
        if packet.haslayer(IP):
            req.origin = packet[IP].src
        else:
            req.origin = 'localhost'
        
        # Extract request details
        req.host = urllib.parse.unquote(packet[HTTPRequest].Host.decode())
        req.request = urllib.parse.unquote(packet[HTTPRequest].Path.decode())
        req.method = packet[HTTPRequest].Method.decode()
        req.headers = get_header(packet)
        
        # Extract body if present
        if packet.haslayer(Raw):
            try:
                req.body = packet[Raw].load.decode()
            except:
                req.body = None
        
        # ========================================================
        # STAGE 2: FEATURE EXTRACTION
        # ========================================================
        features = feature_extractor.extract_features(req)
        
        # ========================================================
        # STAGE 3: RL POLICY DECISION
        # ========================================================
        # RL agent selects action based on extracted features
        rl_action = rl_agent.select_action(features)
        
        # ========================================================
        # STAGE 4: SAFETY LAYER ENFORCEMENT
        # ========================================================
        # Apply hard constraints to prevent dangerous decisions
        safe_action = safety_layer.apply_constraints(
            action=rl_action,
            endpoint=req.request,
            origin=req.origin
        )
        
        # ========================================================
        # STAGE 5: MODE ENFORCEMENT
        # ========================================================
        # MODE A (PASSIVE): Force all actions to LOG_ONLY
        # MODE B (ENFORCEMENT): Use the safe action
        if not RL_ENFORCEMENT_ENABLED:
            final_action = Action.LOG_ONLY  # Passive observation mode
            enforcement_note = "PASSIVE_MODE"
        else:
            final_action = safe_action  # Active enforcement mode
            enforcement_note = "ENFORCEMENT_MODE"
        
        # ========================================================
        # STAGE 6: ACTION EXECUTION
        # ========================================================
        # Execute the chosen action
        request_data = {
            'request': req.request,
            'body': req.body,
            'headers': req.headers
        }
        
        execution_result = action_executor.execute(final_action, request_data)
        
        # ========================================================
        # STAGE 7: RESPONSE CAPTURE (SIMULATED)
        # ========================================================
        # In production, this would capture actual application response
        # For demo, we simulate based on features
        latency_ms = (time.time() - start_time) * 1000
        
        # Estimate if request was an attack using heuristic
        attack_probability = reward_calculator.estimate_attack_probability(features)
        is_likely_attack = attack_probability > 0.5
        
        # Simulate outcome
        outcome = {
            'is_attack': is_likely_attack,
            'attack_probability': attack_probability,
            'http_status': 403 if not execution_result['allowed'] else 200,
            'latency_ms': latency_ms,
            'db_error': False,  # Would be detected from actual response
            'user_complaint': False  # Would come from user feedback
        }
        
        # ========================================================
        # STAGE 8: REWARD CALCULATION
        # ========================================================
        # Calculate reward based on action and outcome
        # This guides the RL agent to learn optimal policies
        reward = reward_calculator.calculate_reward(final_action, outcome)
        
        # ========================================================
        # STAGE 9: ONLINE LEARNING UPDATE
        # ========================================================
        # Update RL agent's Q-table based on observed reward
        # This is where the agent learns from experience
        rl_agent.update(features, final_action, reward)
        
        # ========================================================
        # STAGE 10: LOGGING
        # ========================================================
        # Store request with RL metadata
        req.threats = {
            'rl_action': rl_action.value,
            'safe_action': safe_action.value,
            'final_action': final_action.value,
            'reward': reward,
            'attack_probability': attack_probability,
            'enforcement_mode': enforcement_note,
            'allowed': execution_result['allowed']
        }
        
        # Save to database
        db.save(req)
        
        # Increment counter and checkpoint if needed
        request_count += 1
        if request_count % checkpoint_interval == 0:
            rl_agent.save_checkpoint(RL_CHECKPOINT_FILE)
            print(f"[INFO] Checkpoint saved after {request_count} requests")
        
        # Log summary (for monitoring)
        print(f"[REQ {request_count}] {req.method} {req.request[:50]} | "
              f"RL:{rl_action.value} → Safe:{safe_action.value} → Final:{final_action.value} | "
              f"Reward:{reward:+.2f} | Attack:{attack_probability:.2f}")
    
    except Exception as e:
        # ========================================================
        # ERROR HANDLING: FAIL OPEN
        # ========================================================
        # If RL pipeline crashes, allow request through for safety
        # Log error for debugging
        print(f"[ERROR] RL pipeline failed: {e}")
        print(traceback.format_exc())
        
        # Create minimal request object and allow through
        try:
            req = Request()
            req.origin = 'error'
            req.request = 'RL_PIPELINE_ERROR'
            req.threats = {'error': str(e)}
            db.save(req)
        except:
            pass  # Even logging failed, just continue

# ============================================================
# START SNIFFING
# ============================================================

print(f"[INFO] Starting RL-based WAF on port {args.port}")
print(f"[INFO] Enforcement: {'ENABLED' if RL_ENFORCEMENT_ENABLED else 'DISABLED (PASSIVE)'}")
print(f"[INFO] Exploration rate: {args.epsilon}")
print(f"[INFO] Press Ctrl+C to stop")
print("=" * 60)

try:
    # Start packet capture
    pkgs = sniff(
        prn=process_request_with_rl,
        iface='lo',
        filter=f'port {args.port} and inbound',
        session=TCPSession
    )
finally:
    # Cleanup: save final checkpoint
    rl_agent.save_checkpoint(RL_CHECKPOINT_FILE)
    print(f"\n[INFO] Final checkpoint saved to {RL_CHECKPOINT_FILE}")
    
    # Print final statistics
    stats = rl_agent.get_statistics()
    exec_stats = action_executor.get_statistics()
    
    print("\n" + "=" * 60)
    print("RL AGENT STATISTICS")
    print("=" * 60)
    print(f"Total requests processed: {request_count}")
    print(f"Total Q-table updates: {stats['total_updates']}")
    print(f"States learned: {stats['q_table_size']}")
    print(f"Exploration ratio: {stats['exploration_ratio']:.2%}")
    print(f"\nAction distribution:")
    for action, count in exec_stats['action_counts'].items():
        print(f"  {action}: {count}")
    
    # Close database
    db.close()
    print("\n[INFO] WAF stopped gracefully")
