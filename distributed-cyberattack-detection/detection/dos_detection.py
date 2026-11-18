from datetime import datetime, timedelta
from database import get_db_connection
from config import Config
from detection.detection_engine import create_attack_alert

def detect_dos(source_ip, agent_id):
    """Detect DoS: very high traffic from single IP in short window."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        window_start = datetime.now() - timedelta(seconds=Config.DOS_WINDOW)
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM network_events WHERE source_ip=%s AND timestamp >= %s",
            (source_ip, window_start)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row and row['cnt'] >= Config.DOS_THRESHOLD:
            return create_attack_alert(
                source_ip=source_ip,
                attack_type='DOS',
                severity='CRITICAL',
                description=f"DoS attack detected: {row['cnt']} packets from {source_ip} in {Config.DOS_WINDOW}s (threshold: {Config.DOS_THRESHOLD})",
                agent_id=agent_id
            )
    except Exception as e:
        print(f"DoS detection error: {e}")
    return None
