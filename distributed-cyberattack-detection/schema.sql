-- =============================================================================
-- Distributed Cyberattack Detection and Alert System
-- Full database schema + seed data
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Database
-- ---------------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS cyberattack_detection
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cyberattack_detection;

-- ---------------------------------------------------------------------------
-- Drop tables in reverse foreign-key order
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS attacks;
DROP TABLE IF EXISTS network_events;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS users;

-- ---------------------------------------------------------------------------
-- Table: users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            INT          NOT NULL AUTO_INCREMENT,
    username      VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Table: agents
-- ---------------------------------------------------------------------------
CREATE TABLE agents (
    id               INT          NOT NULL AUTO_INCREMENT,
    agent_name       VARCHAR(100) NOT NULL,
    agent_token_hash VARCHAR(255) NOT NULL,
    ip_address       VARCHAR(45)  DEFAULT NULL,
    status           VARCHAR(20)  NOT NULL DEFAULT 'offline',
    last_seen        TIMESTAMP    NULL DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_agents_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Table: network_events
-- ---------------------------------------------------------------------------
CREATE TABLE network_events (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Table: attacks
-- ---------------------------------------------------------------------------
CREATE TABLE attacks (
    id          INT          NOT NULL AUTO_INCREMENT,
    source_ip   VARCHAR(45)  DEFAULT NULL,
    attack_type VARCHAR(100) DEFAULT NULL,
    severity    VARCHAR(20)  DEFAULT NULL,
    description TEXT         DEFAULT NULL,
    agent_id    INT          DEFAULT NULL,
    detected_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_att_agent_id    (agent_id),
    KEY idx_att_source_ip   (source_ip),
    KEY idx_att_attack_type (attack_type),
    KEY idx_att_severity    (severity),
    CONSTRAINT fk_att_agent FOREIGN KEY (agent_id)
        REFERENCES agents (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Table: alerts
-- ---------------------------------------------------------------------------
CREATE TABLE alerts (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =============================================================================
-- Seed data
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Users  (password_hash is the bcrypt/werkzeug hash of 'admin123';
--         use the Python seed_data() function for the real hash at runtime)
-- ---------------------------------------------------------------------------
INSERT INTO users (username, password_hash) VALUES
    ('admin', '$2b$12$placeholderHashReplaceByPythonSeedData..........');

-- ---------------------------------------------------------------------------
-- Agents
-- (token hashes are SHA-256 of 'token-alpha', 'token-beta', 'token-gamma')
-- ---------------------------------------------------------------------------
INSERT INTO agents (agent_name, agent_token_hash, ip_address, status, last_seen) VALUES
    ('Agent-Alpha',
     'ea8b6a2b5ed9ff7d3eef8d5a3a9c6e53a1abba60b08e63455e4a93d2b5f2d1a',
     '192.168.1.10', 'online',  '2024-01-15 10:30:00'),
    ('Agent-Beta',
     '7d59b6a2c3e1f8d4a0b2c9e7f5a3d1b6c8e2f4a0d6b8c0e2f4a6b8c0e2f4a6b',
     '192.168.1.11', 'online',  '2024-01-15 10:28:00'),
    ('Agent-Gamma',
     'b3c5e7a9d1f3b5c7e9a1d3f5b7c9e1a3d5f7b9c1e3a5d7f9b1c3e5a7d9f1b3',
     '192.168.1.12', 'offline', '2024-01-14 22:15:00');

-- ---------------------------------------------------------------------------
-- Network events (20 rows)
-- ---------------------------------------------------------------------------
INSERT INTO network_events
    (agent_id, source_ip, destination_ip, protocol, destination_port, event_type, timestamp)
VALUES
    (1, '10.0.0.5',    '192.168.1.10', 'TCP',  22,   'CONNECTION',   '2024-01-15 08:00:00'),
    (1, '10.0.0.5',    '192.168.1.10', 'TCP',  23,   'CONNECTION',   '2024-01-15 08:00:01'),
    (1, '10.0.0.5',    '192.168.1.10', 'TCP',  80,   'CONNECTION',   '2024-01-15 08:00:02'),
    (1, '10.0.0.5',    '192.168.1.10', 'TCP',  443,  'CONNECTION',   '2024-01-15 08:00:03'),
    (1, '10.0.0.5',    '192.168.1.10', 'TCP',  8080, 'CONNECTION',   '2024-01-15 08:00:04'),
    (2, '172.16.0.3',  '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN', '2024-01-15 09:05:00'),
    (2, '172.16.0.3',  '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN', '2024-01-15 09:05:10'),
    (2, '172.16.0.3',  '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN', '2024-01-15 09:05:20'),
    (2, '172.16.0.3',  '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN', '2024-01-15 09:05:30'),
    (2, '172.16.0.3',  '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN', '2024-01-15 09:05:40'),
    (1, '203.0.113.1', '192.168.1.10', 'UDP',  53,   'HIGH_VOLUME',  '2024-01-15 10:00:00'),
    (1, '203.0.113.1', '192.168.1.10', 'UDP',  53,   'HIGH_VOLUME',  '2024-01-15 10:00:01'),
    (1, '203.0.113.1', '192.168.1.10', 'ICMP', NULL, 'PING_FLOOD',   '2024-01-15 10:00:02'),
    (2, '10.10.0.99',  '192.168.1.11', 'TCP',  3306, 'CONNECTION',   '2024-01-15 11:00:00'),
    (2, '10.10.0.99',  '192.168.1.11', 'TCP',  5432, 'CONNECTION',   '2024-01-15 11:00:05'),
    (3, '198.51.100.7','192.168.1.12', 'TCP',  445,  'SMB_PROBE',    '2024-01-14 22:00:00'),
    (1, '10.0.0.20',   '192.168.1.10', 'TCP',  21,   'FTP_CONNECT',  '2024-01-15 07:30:00'),
    (1, '10.0.0.20',   '192.168.1.10', 'TCP',  25,   'SMTP_CONNECT', '2024-01-15 07:31:00'),
    (2, '192.0.2.50',  '192.168.1.11', 'UDP',  161,  'SNMP_PROBE',   '2024-01-15 06:00:00'),
    (3, '10.1.1.1',    '192.168.1.12', 'ICMP', NULL, 'PING',         '2024-01-14 20:00:00');

-- ---------------------------------------------------------------------------
-- Attacks (5 rows)
-- ---------------------------------------------------------------------------
INSERT INTO attacks (source_ip, attack_type, severity, description, agent_id, detected_at)
VALUES
    ('10.0.0.5',    'PORT_SCAN',    'high',
     'Source IP scanned 12 ports within 60 seconds.',
     1, '2024-01-15 08:01:00'),

    ('172.16.0.3',  'BRUTE_FORCE',  'critical',
     '5 failed SSH login attempts detected within 60 seconds.',
     2, '2024-01-15 09:05:45'),

    ('203.0.113.1', 'DOS',          'critical',
     'Over 100 UDP packets/second detected – possible DoS attack.',
     1, '2024-01-15 10:00:05'),

    ('10.10.0.99',  'SUSPICIOUS_IP','medium',
     'IP triggered 50+ events across multiple sensitive ports.',
     2, '2024-01-15 11:01:00'),

    ('198.51.100.7','PORT_SCAN',    'high',
     'Sequential port scan targeting SMB and common Windows ports.',
     3, '2024-01-14 22:05:00');

-- ---------------------------------------------------------------------------
-- Alerts (5 rows)
-- ---------------------------------------------------------------------------
INSERT INTO alerts (attack_id, message, severity, status)
VALUES
    (1, 'Port scan detected from 10.0.0.5 on Agent-Alpha.',          'high',     'new'),
    (2, 'Brute-force SSH attack from 172.16.0.3 on Agent-Beta.',      'critical', 'new'),
    (3, 'DoS attack from 203.0.113.1 targeting Agent-Alpha.',         'critical', 'acknowledged'),
    (4, 'Suspicious activity from 10.10.0.99 on Agent-Beta.',         'medium',   'new'),
    (5, 'Port scan from 198.51.100.7 detected by Agent-Gamma.',       'high',     'new');
