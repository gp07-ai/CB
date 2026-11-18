import hashlib
from datetime import datetime

import mysql.connector
from werkzeug.security import generate_password_hash

from config import Config


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_db_connection(dictionary: bool = True) -> mysql.connector.MySQLConnection:
    """Return a new MySQL connection using settings from Config."""
    conn = mysql.connector.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        database=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
    )
    # mysql-connector-python doesn't have a single 'dictionary' kwarg at
    # connect(); callers should open cursors with cursor(dictionary=True).
    # We store the preference as an attribute for convenience.
    conn._use_dict_cursor = dictionary  # type: ignore[attr-defined]
    return conn


def _cursor(conn):
    """Return a cursor that respects the dictionary setting on *conn*."""
    use_dict = getattr(conn, '_use_dict_cursor', True)
    return conn.cursor(dictionary=use_dict)


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create all required tables if they do not already exist."""
    conn = get_db_connection(dictionary=False)
    cur = conn.cursor()

    # users ----------------------------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INT          NOT NULL AUTO_INCREMENT,
            username      VARCHAR(100) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_users_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # agents ---------------------------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id               INT          NOT NULL AUTO_INCREMENT,
            agent_name       VARCHAR(100) NOT NULL,
            agent_token_hash VARCHAR(255) NOT NULL,
            ip_address       VARCHAR(45)  DEFAULT NULL,
            status           VARCHAR(20)  NOT NULL DEFAULT 'offline',
            last_seen        TIMESTAMP    NULL DEFAULT NULL,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # network_events -------------------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_events (
            id               INT         NOT NULL AUTO_INCREMENT,
            agent_id         INT         DEFAULT NULL,
            source_ip        VARCHAR(45) DEFAULT NULL,
            destination_ip   VARCHAR(45) DEFAULT NULL,
            protocol         VARCHAR(20) DEFAULT NULL,
            destination_port INT         DEFAULT NULL,
            event_type       VARCHAR(50) DEFAULT NULL,
            timestamp        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_ne_agent_id  (agent_id),
            KEY idx_ne_source_ip (source_ip),
            KEY idx_ne_timestamp (timestamp),
            CONSTRAINT fk_ne_agent FOREIGN KEY (agent_id)
                REFERENCES agents (id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # attacks --------------------------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id          INT          NOT NULL AUTO_INCREMENT,
            source_ip   VARCHAR(45)  DEFAULT NULL,
            attack_type VARCHAR(100) DEFAULT NULL,
            severity    VARCHAR(20)  DEFAULT NULL,
            description TEXT         DEFAULT NULL,
            agent_id    INT          DEFAULT NULL,
            detected_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_att_agent_id   (agent_id),
            KEY idx_att_source_ip  (source_ip),
            KEY idx_att_attack_type(attack_type),
            CONSTRAINT fk_att_agent FOREIGN KEY (agent_id)
                REFERENCES agents (id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # alerts ---------------------------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id         INT         NOT NULL AUTO_INCREMENT,
            attack_id  INT         DEFAULT NULL,
            message    TEXT        DEFAULT NULL,
            severity   VARCHAR(20) DEFAULT NULL,
            status     VARCHAR(20) NOT NULL DEFAULT 'new',
            created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_al_attack_id (attack_id),
            KEY idx_al_status    (status),
            CONSTRAINT fk_al_attack FOREIGN KEY (attack_id)
                REFERENCES attacks (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    conn.commit()
    cur.close()
    conn.close()


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def seed_data() -> None:
    """Populate tables with demo data if the database is empty."""
    conn = get_db_connection(dictionary=False)
    cur = conn.cursor()

    # Check if already seeded
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    if count > 0:
        cur.close()
        conn.close()
        return

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------
    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
        ('admin', generate_password_hash('admin123')),
    )

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------
    agents = [
        ('Agent-Alpha', _sha256('token-alpha'), '192.168.1.10', 'online',
         datetime(2024, 1, 15, 10, 30, 0)),
        ('Agent-Beta',  _sha256('token-beta'),  '192.168.1.11', 'online',
         datetime(2024, 1, 15, 10, 28, 0)),
        ('Agent-Gamma', _sha256('token-gamma'), '192.168.1.12', 'offline',
         datetime(2024, 1, 14, 22, 15, 0)),
    ]
    cur.executemany(
        """INSERT INTO agents (agent_name, agent_token_hash, ip_address, status, last_seen)
           VALUES (%s, %s, %s, %s, %s)""",
        agents,
    )

    # ------------------------------------------------------------------
    # Network events (20 rows)
    # ------------------------------------------------------------------
    network_events = [
        # (agent_id, source_ip, destination_ip, protocol, dst_port, event_type, timestamp)
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  22,   'CONNECTION',       datetime(2024, 1, 15, 8,  0,  0)),
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  23,   'CONNECTION',       datetime(2024, 1, 15, 8,  0,  1)),
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  80,   'CONNECTION',       datetime(2024, 1, 15, 8,  0,  2)),
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  443,  'CONNECTION',       datetime(2024, 1, 15, 8,  0,  3)),
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  8080, 'CONNECTION',       datetime(2024, 1, 15, 8,  0,  4)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5,  0)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5, 10)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5, 20)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5, 30)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5, 40)),
        (1, '203.0.113.1','192.168.1.10', 'UDP',  53,   'HIGH_VOLUME',      datetime(2024, 1, 15, 10, 0,  0)),
        (1, '203.0.113.1','192.168.1.10', 'UDP',  53,   'HIGH_VOLUME',      datetime(2024, 1, 15, 10, 0,  1)),
        (1, '203.0.113.1','192.168.1.10', 'ICMP', None, 'PING_FLOOD',       datetime(2024, 1, 15, 10, 0,  2)),
        (2, '10.10.0.99', '192.168.1.11', 'TCP',  3306, 'CONNECTION',       datetime(2024, 1, 15, 11, 0,  0)),
        (2, '10.10.0.99', '192.168.1.11', 'TCP',  5432, 'CONNECTION',       datetime(2024, 1, 15, 11, 0,  5)),
        (3, '198.51.100.7','192.168.1.12','TCP',  445,  'SMB_PROBE',        datetime(2024, 1, 14, 22, 0,  0)),
        (1, '10.0.0.20',  '192.168.1.10', 'TCP',  21,   'FTP_CONNECT',      datetime(2024, 1, 15, 7, 30,  0)),
        (1, '10.0.0.20',  '192.168.1.10', 'TCP',  25,   'SMTP_CONNECT',     datetime(2024, 1, 15, 7, 31,  0)),
        (2, '192.0.2.50', '192.168.1.11', 'UDP',  161,  'SNMP_PROBE',       datetime(2024, 1, 15, 6,  0,  0)),
        (3, '10.1.1.1',   '192.168.1.12', 'ICMP', None, 'PING',             datetime(2024, 1, 14, 20, 0,  0)),
    ]
    cur.executemany(
        """INSERT INTO network_events
               (agent_id, source_ip, destination_ip, protocol,
                destination_port, event_type, timestamp)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        network_events,
    )

    # ------------------------------------------------------------------
    # Attacks (5 rows)
    # ------------------------------------------------------------------
    attacks = [
        ('10.0.0.5',    'PORT_SCAN',    'high',   'Source IP scanned 12 ports within 60 seconds.',               1, datetime(2024, 1, 15,  8,  1, 0)),
        ('172.16.0.3',  'BRUTE_FORCE',  'critical','5 failed SSH login attempts detected within 60 seconds.',     2, datetime(2024, 1, 15,  9,  5, 45)),
        ('203.0.113.1', 'DOS',          'critical','Over 100 UDP packets/second detected – possible DoS attack.',  1, datetime(2024, 1, 15, 10,  0, 5)),
        ('10.10.0.99',  'SUSPICIOUS_IP','medium',  'IP triggered 50+ events across multiple sensitive ports.',    2, datetime(2024, 1, 15, 11,  1, 0)),
        ('198.51.100.7','PORT_SCAN',    'high',    'Sequential port scan targeting SMB and common Windows ports.', 3, datetime(2024, 1, 14, 22,  5, 0)),
    ]
    cur.executemany(
        """INSERT INTO attacks
               (source_ip, attack_type, severity, description, agent_id, detected_at)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        attacks,
    )

    # ------------------------------------------------------------------
    # Alerts (5 rows, one per attack; attack IDs are 1-5 after insert)
    # ------------------------------------------------------------------
    alerts = [
        (1, 'Port scan detected from 10.0.0.5 on Agent-Alpha.',           'high',     'new'),
        (2, 'Brute-force SSH attack from 172.16.0.3 on Agent-Beta.',       'critical', 'new'),
        (3, 'DoS attack from 203.0.113.1 targeting Agent-Alpha.',          'critical', 'acknowledged'),
        (4, 'Suspicious activity from 10.10.0.99 on Agent-Beta.',          'medium',   'new'),
        (5, 'Port scan from 198.51.100.7 detected by Agent-Gamma.',        'high',     'new'),
    ]
    cur.executemany(
        """INSERT INTO alerts (attack_id, message, severity, status)
           VALUES (%s, %s, %s, %s)""",
        alerts,
    )

    conn.commit()
    cur.close()
    conn.close()
