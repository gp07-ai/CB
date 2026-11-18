from datetime import datetime, timedelta
from database import get_db_connection
from config import Config

def analyze_event(event_data, agent_id):
    """Main analysis function - runs all detection rules on a new event."""
    from detection.port_scan import detect_port_scan
    from detection.brute_force import detect_brute_force
    from detection.dos_detection import detect_dos

    alerts_generated = []
    source_ip = event_data.get('source_ip')
    event_type = event_data.get('event_type', '')
    protocol = event_data.get('protocol', '')
    dest_port = event_data.get('destination_port', 0)
    
    # Run all detectors
    ps_alert = detect_port_scan(source_ip, agent_id)
    if ps_alert:
        alerts_generated.append(ps_alert)
    
    if event_type in ('LOGIN_FAILED', 'AUTH_FAILURE', 'BRUTE_FORCE'):
        bf_alert = detect_brute_force(source_ip, agent_id)
        if bf_alert:
            alerts_generated.append(bf_alert)
    
    dos_alert = detect_dos(source_ip, agent_id)
    if dos_alert:
        alerts_generated.append(dos_alert)
    
    # Suspicious IP detection
    susp_alert = detect_suspicious_ip(source_ip, agent_id)
    if susp_alert:
        alerts_generated.append(susp_alert)
    
    return alerts_generated

def detect_suspicious_ip(source_ip, agent_id):
    """Detect IPs with excessive overall event count."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        window_start = datetime.now() - timedelta(seconds=Config.PORT_SCAN_WINDOW * 5)
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM network_events WHERE source_ip=%s AND timestamp >= %s",
            (source_ip, window_start)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row and row['cnt'] >= Config.SUSPICIOUS_IP_THRESHOLD:
            return create_attack_alert(
                source_ip=source_ip,
                attack_type='SUSPICIOUS_IP',
                severity='MEDIUM',
                description=f"IP {source_ip} generated {row['cnt']} events in 5 minutes (threshold: {Config.SUSPICIOUS_IP_THRESHOLD})",
                agent_id=agent_id
            )
    except Exception as e:
        print(f"Suspicious IP detection error: {e}")
    return None

def create_attack_alert(source_ip, attack_type, severity, description, agent_id):
    """Create attack record and corresponding alert in DB, return alert dict."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if same attack type from same IP in last 5 mins to avoid duplicates
        window_start = datetime.now() - timedelta(minutes=5)
        cursor.execute(
            "SELECT id FROM attacks WHERE source_ip=%s AND attack_type=%s AND detected_at >= %s",
            (source_ip, attack_type, window_start)
        )
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return None
        
        # Insert attack
        cursor.execute(
            "INSERT INTO attacks (source_ip, attack_type, severity, description, agent_id) VALUES (%s,%s,%s,%s,%s)",
            (source_ip, attack_type, severity, description, agent_id)
        )
        attack_id = cursor.lastrowid
        
        # Insert alert
        message = f"[{severity}] {attack_type} detected from {source_ip}: {description}"
        cursor.execute(
            "INSERT INTO alerts (attack_id, message, severity) VALUES (%s,%s,%s)",
            (attack_id, message, severity)
        )
        conn.commit()
        
        alert = {
            'attack_id': attack_id,
            'attack_type': attack_type,
            'severity': severity,
            'source_ip': source_ip,
            'message': message,
            'detected_at': datetime.now().isoformat()
        }
        cursor.close()
        conn.close()
        return alert
    except Exception as e:
        print(f"Error creating attack alert: {e}")
        return None
