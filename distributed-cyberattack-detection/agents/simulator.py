#!/usr/bin/env python3
"""
Attack Simulator for demonstration purposes.
Simulates various cyberattack patterns by sending events to the central server.
FOR EDUCATIONAL USE ONLY - all events are simulated, no real attacks.
"""
import requests
import time
import random
import argparse
from datetime import datetime

CENTRAL_SERVER = 'http://localhost:5000'

# Predefined agent tokens (must match what was registered in DB)
AGENTS = [
    {'id': 1, 'token': 'token-alpha', 'name': 'Agent-Alpha'},
    {'id': 2, 'token': 'token-beta',  'name': 'Agent-Beta'},
    {'id': 3, 'token': 'token-gamma', 'name': 'Agent-Gamma'},
]

def send_event(agent_id, agent_token, source_ip, dest_ip, protocol, dest_port, event_type):
    payload = {
        'agent_id': agent_id,
        'agent_token': agent_token,
        'source_ip': source_ip,
        'destination_ip': dest_ip,
        'protocol': protocol,
        'destination_port': dest_port,
        'event_type': event_type,
        'timestamp': datetime.now().isoformat()
    }
    try:
        r = requests.post(f'{CENTRAL_SERVER}/api/agents/submit_event', json=payload, timeout=5)
        return r.json()
    except Exception as e:
        print(f"Error sending event: {e}")
        return None

def simulate_port_scan(agent=None):
    """Simulate port scanning from one IP across many ports."""
    agent = agent or random.choice(AGENTS)
    attacker_ip = f"10.0.0.{random.randint(100,200)}"
    target_ip = f"192.168.1.{random.randint(1,50)}"
    print(f"\n[SIM] Port Scan: {attacker_ip} -> {target_ip} via {agent['name']}")
    ports = random.sample(range(1, 65535), 15)
    for port in ports:
        send_event(agent['id'], agent['token'], attacker_ip, target_ip, 'TCP', port, 'CONNECTION_ATTEMPT')
        time.sleep(0.1)
    print(f"[SIM] Port scan complete: probed {len(ports)} ports")

def simulate_brute_force(agent=None):
    """Simulate brute force login attempts."""
    agent = agent or random.choice(AGENTS)
    attacker_ip = f"10.0.1.{random.randint(1,50)}"
    target_ip = "192.168.1.1"
    print(f"\n[SIM] Brute Force: {attacker_ip} -> {target_ip} via {agent['name']}")
    for i in range(8):
        send_event(agent['id'], agent['token'], attacker_ip, target_ip, 'TCP', 22, 'LOGIN_FAILED')
        time.sleep(0.2)
    print("[SIM] Brute force simulation complete")

def simulate_dos(agent=None):
    """Simulate a DoS flood (simulated, no real traffic)."""
    agent = agent or random.choice(AGENTS)
    attacker_ip = f"172.16.0.{random.randint(1,100)}"
    target_ip = "192.168.1.1"
    print(f"\n[SIM] DoS Attack: {attacker_ip} -> {target_ip} via {agent['name']}")
    for i in range(120):
        send_event(agent['id'], agent['token'], attacker_ip, target_ip, 'UDP', 80, 'HIGH_TRAFFIC')
        time.sleep(0.05)
    print("[SIM] DoS simulation complete")

def simulate_normal_traffic(agent=None, count=20):
    """Simulate normal background traffic."""
    agent = agent or random.choice(AGENTS)
    print(f"\n[SIM] Normal Traffic via {agent['name']}: {count} events")
    for _ in range(count):
        src = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
        dst = f"8.8.{random.randint(1,10)}.{random.randint(1,10)}"
        proto = random.choice(['TCP', 'UDP', 'ICMP'])
        port = random.choice([80, 443, 8080, 53, 22, 25])
        etype = random.choice(['HTTP_REQUEST', 'DNS_QUERY', 'PING', 'HTTPS_REQUEST'])
        send_event(agent['id'], agent['token'], src, dst, proto, port, etype)
        time.sleep(0.1)

def run_full_demo():
    """Run a complete demo sequence of all attack types."""
    print("=" * 60)
    print("CYBERATTACK DETECTION SYSTEM - DEMO SIMULATION")
    print("FOR EDUCATIONAL USE ONLY")
    print("=" * 60)
    print("\nStep 1: Generating normal background traffic...")
    simulate_normal_traffic(count=10)
    time.sleep(2)
    print("\nStep 2: Simulating Port Scan attack...")
    simulate_port_scan()
    time.sleep(5)
    print("\nStep 3: Simulating Brute Force attack...")
    simulate_brute_force()
    time.sleep(5)
    print("\nStep 4: Simulating DoS attack (simulated events only)...")
    simulate_dos()
    time.sleep(5)
    print("\nStep 5: More normal traffic...")
    simulate_normal_traffic(count=10)
    print("\n[DEMO COMPLETE] Check the dashboard at http://localhost:5000")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cyberattack Simulator (Educational)')
    parser.add_argument('--attack', choices=['port_scan', 'brute_force', 'dos', 'normal', 'all'], default='all')
    parser.add_argument('--server', default='http://localhost:5000')
    args = parser.parse_args()
    CENTRAL_SERVER = args.server

    if args.attack == 'port_scan':
        simulate_port_scan()
    elif args.attack == 'brute_force':
        simulate_brute_force()
    elif args.attack == 'dos':
        simulate_dos()
    elif args.attack == 'normal':
        simulate_normal_traffic()
    else:
        run_full_demo()
