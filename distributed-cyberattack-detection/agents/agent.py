#!/usr/bin/env python3
"""
Monitoring Agent for the Distributed Cyberattack Detection System.
Collects simulated network events and reports them to the central server.
"""
import requests
import time
import random
import threading
from datetime import datetime
import agent_config


class AgentMonitor:
    def __init__(self):
        self.server_url = agent_config.CENTRAL_SERVER_URL
        self.agent_id = agent_config.AGENT_ID
        self.agent_token = agent_config.AGENT_TOKEN
        self.agent_name = agent_config.AGENT_NAME
        self.running = False

    def register(self):
        """Register this agent with the central server."""
        url = f"{self.server_url}/api/agents/register"
        payload = {
            'agent_name': self.agent_name,
            'agent_token': self.agent_token,
        }
        try:
            response = requests.post(url, json=payload, timeout=10)
            result = response.json()
            print(f"[REGISTER] Response: {result}")
            return result
        except Exception as e:
            print(f"[REGISTER] Error: {e}")
            return None

    def send_heartbeat(self):
        """Send a heartbeat to the central server to indicate this agent is alive."""
        url = f"{self.server_url}/api/agents/heartbeat"
        payload = {
            'agent_id': self.agent_id,
            'agent_token': self.agent_token,
        }
        try:
            response = requests.post(url, json=payload, timeout=10)
            result = response.json()
            print(f"[HEARTBEAT] {result}")
        except Exception as e:
            print(f"[HEARTBEAT] Error: {e}")

    def send_event(self, event_data):
        """Send a network event to the central server."""
        url = f"{self.server_url}/api/agents/submit_event"
        payload = {**event_data, 'agent_id': self.agent_id, 'agent_token': self.agent_token}
        try:
            response = requests.post(url, json=payload, timeout=10)
            return response.json()
        except Exception as e:
            print(f"[SEND_EVENT] Error: {e}")
            return None

    def heartbeat_loop(self):
        """Background thread: send periodic heartbeats."""
        while self.running:
            self.send_heartbeat()
            time.sleep(agent_config.HEARTBEAT_INTERVAL)

    def collect_event(self):
        """Generate a simulated network event."""
        source_ips = [
            '192.168.1.100', '10.0.0.50', '172.16.0.5',
            '10.0.1.20', '192.168.2.200', '203.0.113.42',
        ]
        event_types = [
            'CONNECTION_ATTEMPT', 'LOGIN_FAILED', 'HIGH_TRAFFIC',
            'HTTP_REQUEST', 'DNS_QUERY', 'PING', 'HTTPS_REQUEST',
        ]
        protocols = ['TCP', 'UDP', 'ICMP']
        common_ports = [22, 80, 443, 8080, 53, 3306, 3389, 21, 25, 110]

        return {
            'source_ip': random.choice(source_ips),
            'destination_ip': f"192.168.1.{random.randint(1, 50)}",
            'protocol': random.choice(protocols),
            'destination_port': random.choice(common_ports),
            'event_type': random.choice(event_types),
            'timestamp': datetime.now().isoformat(),
        }

    def run(self):
        """Main loop: collect and send events, with a heartbeat thread running in parallel."""
        self.running = True

        # Start heartbeat in background
        hb_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        hb_thread.start()
        print(f"[AGENT] {self.agent_name} running. Sending events every {agent_config.EVENT_SEND_INTERVAL}s.")

        while self.running:
            event = self.collect_event()
            result = self.send_event(event)
            if result:
                print(f"[EVENT] Sent {event['event_type']} from {event['source_ip']} -> response: {result}")
            else:
                print(f"[EVENT] Failed to send event for {event['event_type']}")
            time.sleep(agent_config.EVENT_SEND_INTERVAL)

    def stop(self):
        """Stop the agent gracefully."""
        self.running = False
        print(f"[AGENT] {self.agent_name} stopped.")


if __name__ == '__main__':
    monitor = AgentMonitor()
    try:
        monitor.register()
        monitor.run()
    except KeyboardInterrupt:
        monitor.stop()
        print("[AGENT] Exiting.")
