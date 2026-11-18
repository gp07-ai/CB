from datetime import datetime, timedelta
from database import get_db_connection
from config import Config
from detection.detection_engine import create_attack_alert

def detect_brute_force(source_ip, agent_id):
    """Detect brute force: repeated LOGIN_FAILED events from same IP."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        window_start = datetime.now() - timedelta(seconds=Config.BRUTE_FORCE_WINDOW)
        cursor.execute(
            """SELECT COUNT(*) as cnt FROM network_events 
               WHERE source_ip=%s AND event_type IN ('LOGIN_FAILED','AUTH_FAILURE','BRUTE_FORCE') 
               AND timestamp >= %s""",
            (source_ip, window_start)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row and row['cnt'] >= Config.BRUTE_FORCE_THRESHOLD:
            return create_attack_alert(
                source_ip=source_ip,
                attack_type='BRUTE_FORCE',
                severity='HIGH',
                description=f"Brute force attack: {row['cnt']} failed login attempts in {Config.BRUTE_FORCE_WINDOW}s (threshold: {Config.BRUTE_FORCE_THRESHOLD})",
                agent_id=agent_id
            )
    except Exception as e:
        print(f"Brute force detection error: {e}")
    return None
