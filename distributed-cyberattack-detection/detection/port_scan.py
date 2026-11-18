from datetime import datetime, timedelta
from database import get_db_connection
from config import Config
from detection.detection_engine import create_attack_alert

def detect_port_scan(source_ip, agent_id):
    """Detect port scanning: same IP hitting many different ports in time window."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        window_start = datetime.now() - timedelta(seconds=Config.PORT_SCAN_WINDOW)
        cursor.execute(
            """SELECT COUNT(DISTINCT destination_port) as port_count 
               FROM network_events 
               WHERE source_ip=%s AND timestamp >= %s AND destination_port IS NOT NULL""",
            (source_ip, window_start)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if row and row['port_count'] >= Config.PORT_SCAN_THRESHOLD:
            return create_attack_alert(
                source_ip=source_ip,
                attack_type='PORT_SCAN',
                severity='HIGH',
                description=f"Port scan detected: {row['port_count']} unique ports probed in {Config.PORT_SCAN_WINDOW}s (threshold: {Config.PORT_SCAN_THRESHOLD})",
                agent_id=agent_id
            )
    except Exception as e:
        print(f"Port scan detection error: {e}")
    return None
