#!/usr/bin/env python3
"""
Security Log Data Generator for Elastic Incident Response Agent
Generates realistic security events including 5 attack patterns:
1. Brute Force - Single IP hammering one user
2. Credential Stuffing - Single IP trying many usernames
3. Password Spraying - Many IPs trying common passwords
4. Lateral Movement - Post-auth spread to internal hosts
5. Impossible Travel - Same user from distant locations
"""

import random
import time
import json
import argparse
import logging
import warnings
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, asdict
from typing import Generator
import hashlib
from elasticsearch import Elasticsearch, helpers
from elasticsearch.helpers import BulkIndexError

warnings.filterwarnings("ignore")

# =============================================================================
# Configuration
# =============================================================================

@dataclass
class Config:
    """Generator configuration"""
    es_host: str = "https://localhost:9200"
    es_user: str = "elastic"
    es_password: str = ""
    es_index: str = "security-logs"
    verify_certs: bool = False
    
    # Generation settings
    events_per_second: float = 10.0
    total_events: int = 10000
    attack_probability: float = 0.15  # 15% of time windows have attacks
    
    # Output mode: 'elasticsearch', 'stdout', 'file'
    output_mode: str = "elasticsearch"
    output_file: str = "security-logs.ndjson"
    debug: bool = False


# =============================================================================
# Data Pools - Realistic values for generation
# =============================================================================

USERNAMES = [
    "admin", "root", "administrator", "sysadmin", "devops",
    "jsmith", "mwilliams", "bjohnson", "agarcia", "klee",
    "service_account", "jenkins", "deploy", "backup", "monitoring",
    "alice", "bob", "charlie", "david", "eve",
    "hr_system", "finance_api", "sales_bot", "support_user", "guest"
]

INTERNAL_HOSTS = [
    "app-server-01", "app-server-02", "app-server-03",
    "db-primary", "db-replica-01", "db-replica-02",
    "web-frontend-01", "web-frontend-02",
    "jenkins-master", "jenkins-agent-01",
    "monitoring-01", "logging-01",
    "file-server", "mail-server", "vpn-gateway"
]

# External IPs - mix of known bad actors and legitimate
EXTERNAL_IPS = [
    # Suspicious IPs (for attack patterns)
    "185.220.101.42", "45.155.205.117", "194.26.29.113",
    "91.240.118.172", "141.98.10.63", "45.129.56.200",
    "193.27.228.63", "89.248.165.89", "45.95.169.130",
    "194.165.16.98", "185.156.73.54", "91.132.147.168",
    # Legitimate-looking IPs
    "203.0.113.50", "198.51.100.25", "192.0.2.100",
    "172.217.14.110", "151.101.1.140", "104.16.85.20"
]

# Geolocations for impossible travel
GEOLOCATIONS = [
    {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
    {"city": "Los Angeles", "country": "US", "lat": 34.0522, "lon": -118.2437},
    {"city": "London", "country": "GB", "lat": 51.5074, "lon": -0.1278},
    {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
    {"city": "Sydney", "country": "AU", "lat": -33.8688, "lon": 151.2093},
    {"city": "Moscow", "country": "RU", "lat": 55.7558, "lon": 37.6173},
    {"city": "São Paulo", "country": "BR", "lat": -23.5505, "lon": -46.6333},
    {"city": "Mumbai", "country": "IN", "lat": 19.0760, "lon": 72.8777},
]

COMMON_PASSWORDS = [
    "password", "123456", "admin", "letmein", "welcome",
    "password123", "qwerty", "abc123", "monkey", "master"
]

AUTH_METHODS = ["ssh", "rdp", "web_login", "api_key", "vpn", "ldap"]

EVENT_OUTCOMES = ["success", "failure"]


# =============================================================================
# Event Generation
# =============================================================================

@dataclass
class SecurityEvent:
    """Represents a single security log event"""
    timestamp: str
    event_type: str
    outcome: str
    source_ip: str
    source_geo: dict
    destination_host: str
    username: str
    auth_method: str
    failure_reason: str | None
    session_id: str | None
    attack_pattern: str | None  # For labeling/debugging
    
    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


def generate_session_id() -> str:
    """Generate a realistic session ID"""
    return hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:16]


def format_timestamp_es(dt: datetime) -> str:
    """Format datetime for Elasticsearch date field (strict_date_optional_time: ...Z or epoch_millis)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def random_geo() -> dict:
    """Return a random geolocation"""
    return random.choice(GEOLOCATIONS).copy()


def generate_normal_event(timestamp: datetime) -> SecurityEvent:
    """Generate a normal (non-attack) authentication event"""
    is_success = random.random() < 0.95  # 95% success rate normally
    geo = random_geo()
    
    return SecurityEvent(
        timestamp=format_timestamp_es(timestamp),
        event_type="authentication",
        outcome="success" if is_success else "failure",
        source_ip=random.choice(EXTERNAL_IPS[12:]),  # Use "legitimate" IPs
        source_geo=geo,
        destination_host=random.choice(INTERNAL_HOSTS),
        username=random.choice(USERNAMES),
        auth_method=random.choice(AUTH_METHODS),
        failure_reason=None if is_success else random.choice([
            "invalid_password", "account_locked", "expired_token", "mfa_failed"
        ]),
        session_id=generate_session_id() if is_success else None,
        attack_pattern=None
    )


# =============================================================================
# Attack Pattern Generators
# =============================================================================

def generate_brute_force(base_timestamp: datetime, count: int = 50) -> list[SecurityEvent]:
    """
    Pattern 1: Brute Force
    Single IP attempts many logins against one user in short time
    """
    events = []
    attacker_ip = random.choice(EXTERNAL_IPS[:12])  # Suspicious IP
    target_user = random.choice(USERNAMES[:5])  # Target privileged accounts
    target_host = random.choice(INTERNAL_HOSTS)
    geo = random_geo()
    
    for i in range(count):
        ts = base_timestamp + timedelta(seconds=random.uniform(0, 300))  # 5 min window
        is_success = i == count - 1 and random.random() < 0.1  # Rare success at end
        
        events.append(SecurityEvent(
            timestamp=format_timestamp_es(ts),
            event_type="authentication",
            outcome="success" if is_success else "failure",
            source_ip=attacker_ip,
            source_geo=geo,
            destination_host=target_host,
            username=target_user,
            auth_method=random.choice(["ssh", "rdp", "web_login"]),
            failure_reason=None if is_success else "invalid_password",
            session_id=generate_session_id() if is_success else None,
            attack_pattern="brute_force"
        ))
    
    return events


def generate_credential_stuffing(base_timestamp: datetime, count: int = 40) -> list[SecurityEvent]:
    """
    Pattern 2: Credential Stuffing
    Single IP tries many different username/password combos (from leaked databases)
    """
    events = []
    attacker_ip = random.choice(EXTERNAL_IPS[:12])
    geo = random_geo()
    target_host = random.choice(INTERNAL_HOSTS)
    
    # Shuffle usernames to try many different ones
    usernames_to_try = USERNAMES.copy()
    random.shuffle(usernames_to_try)
    
    for i, username in enumerate(usernames_to_try[:count]):
        ts = base_timestamp + timedelta(seconds=i * random.uniform(2, 8))  # Paced attempts
        is_success = random.random() < 0.05  # Very low success rate
        
        events.append(SecurityEvent(
            timestamp=format_timestamp_es(ts),
            event_type="authentication",
            outcome="success" if is_success else "failure",
            source_ip=attacker_ip,
            source_geo=geo,
            destination_host=target_host,
            username=username,
            auth_method="web_login",
            failure_reason=None if is_success else random.choice([
                "invalid_password", "user_not_found", "invalid_credentials"
            ]),
            session_id=generate_session_id() if is_success else None,
            attack_pattern="credential_stuffing"
        ))
    
    return events


def generate_password_spraying(base_timestamp: datetime, ip_count: int = 15) -> list[SecurityEvent]:
    """
    Pattern 3: Password Spraying
    Many different IPs each try 1-2 common passwords against multiple users
    Distributed to evade single-IP detection
    """
    events = []
    password = random.choice(COMMON_PASSWORDS)  # All attackers use same password
    
    for i in range(ip_count):
        attacker_ip = f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        geo = random_geo()
        target_users = random.sample(USERNAMES, k=random.randint(2, 5))
        
        for j, user in enumerate(target_users):
            ts = base_timestamp + timedelta(seconds=i * 30 + j * random.uniform(1, 5))
            is_success = random.random() < 0.05
            
            events.append(SecurityEvent(
                timestamp=format_timestamp_es(ts),
                event_type="authentication",
                outcome="success" if is_success else "failure",
                source_ip=attacker_ip,
                source_geo=geo,
                destination_host=random.choice(INTERNAL_HOSTS),
                username=user,
                auth_method=random.choice(["web_login", "ldap", "vpn"]),
                failure_reason=None if is_success else "invalid_password",
                session_id=generate_session_id() if is_success else None,
                attack_pattern="password_spraying"
            ))
    
    return events


def generate_lateral_movement(base_timestamp: datetime) -> list[SecurityEvent]:
    """
    Pattern 4: Lateral Movement
    After initial compromise, attacker moves through internal network
    Characterized by: success -> rapid internal auth attempts
    """
    events = []
    attacker_ip = random.choice(EXTERNAL_IPS[:12])
    compromised_user = random.choice(USERNAMES)
    geo = random_geo()
    
    # Initial successful compromise
    events.append(SecurityEvent(
        timestamp=format_timestamp_es(base_timestamp),
        event_type="authentication",
        outcome="success",
        source_ip=attacker_ip,
        source_geo=geo,
        destination_host=random.choice(INTERNAL_HOSTS[:3]),
        username=compromised_user,
        auth_method="vpn",
        failure_reason=None,
        session_id=generate_session_id(),
        attack_pattern="lateral_movement"
    ))
    
    # Now attempt to spread internally
    internal_ip = f"10.0.{random.randint(1,10)}.{random.randint(1,254)}"
    
    for i, target_host in enumerate(random.sample(INTERNAL_HOSTS, k=8)):
        ts = base_timestamp + timedelta(seconds=60 + i * random.uniform(10, 60))
        is_success = random.random() < 0.4  # Higher success rate with valid creds
        
        events.append(SecurityEvent(
            timestamp=format_timestamp_es(ts),
            event_type="authentication",
            outcome="success" if is_success else "failure",
            source_ip=internal_ip,  # Now coming from inside
            source_geo={"city": "Internal", "country": "INTERNAL", "lat": 0, "lon": 0},
            destination_host=target_host,
            username=compromised_user,
            auth_method=random.choice(["ssh", "rdp", "smb"]),
            failure_reason=None if is_success else random.choice([
                "access_denied", "insufficient_privileges", "host_unreachable"
            ]),
            session_id=generate_session_id() if is_success else None,
            attack_pattern="lateral_movement"
        ))
    
    return events


def generate_impossible_travel(base_timestamp: datetime) -> list[SecurityEvent]:
    """
    Pattern 5: Impossible Travel
    Same user authenticates from geographically distant locations
    within impossibly short time (suggests credential compromise)
    """
    events = []
    target_user = random.choice(USERNAMES)
    session = generate_session_id()
    
    # Pick two distant locations
    loc1, loc2 = random.sample(GEOLOCATIONS, k=2)
    
    # First login from location 1
    events.append(SecurityEvent(
        timestamp=format_timestamp_es(base_timestamp),
        event_type="authentication",
        outcome="success",
        source_ip=f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        source_geo=loc1,
        destination_host=random.choice(INTERNAL_HOSTS),
        username=target_user,
        auth_method="vpn",
        failure_reason=None,
        session_id=session,
        attack_pattern="impossible_travel"
    ))
    
    # Second login from distant location 2 within 10-30 minutes
    ts2 = base_timestamp + timedelta(minutes=random.randint(10, 30))
    events.append(SecurityEvent(
        timestamp=format_timestamp_es(ts2),
        event_type="authentication",
        outcome="success",
        source_ip=f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        source_geo=loc2,
        destination_host=random.choice(INTERNAL_HOSTS),
        username=target_user,
        auth_method="vpn",
        failure_reason=None,
        session_id=generate_session_id(),
        attack_pattern="impossible_travel"
    ))
    
    return events


# =============================================================================
# Main Generator
# =============================================================================

ATTACK_GENERATORS = [
    ("brute_force", generate_brute_force),
    ("credential_stuffing", generate_credential_stuffing),
    ("password_spraying", generate_password_spraying),
    ("lateral_movement", generate_lateral_movement),
    ("impossible_travel", generate_impossible_travel),
]


def generate_events(config: Config) -> Generator[SecurityEvent, None, None]:
    """
    Main generator that yields security events over time.
    Mixes normal traffic with periodic attack patterns.
    """
    current_time = datetime.now(timezone.utc)
    events_generated = 0
    attack_buffer = []  # Buffer for attack events to interleave
    
    while events_generated < config.total_events:
        # Check if we should inject an attack pattern
        if not attack_buffer and random.random() < config.attack_probability / 100:
            attack_name, attack_func = random.choice(ATTACK_GENERATORS)
            attack_events = attack_func(current_time)
            attack_buffer.extend(attack_events)
            random.shuffle(attack_buffer)  # Mix up the order slightly
            print(f"[!] Injecting attack pattern: {attack_name} ({len(attack_events)} events)")
        
        # Yield from attack buffer or generate normal event
        if attack_buffer and random.random() < 0.3:
            yield attack_buffer.pop(0)
        else:
            yield generate_normal_event(current_time)
        
        events_generated += 1
        
        # Advance time
        current_time += timedelta(seconds=1 / config.events_per_second)


def create_index_mapping() -> dict:
    """Return Elasticsearch index mapping for security-logs"""
    return {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "event_type": {"type": "keyword"},
                "outcome": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "source_geo": {
                    "properties": {
                        "city": {"type": "keyword"},
                        "country": {"type": "keyword"},
                        "lat": {"type": "float"},
                        "lon": {"type": "float"}
                    }
                },
                "destination_host": {"type": "keyword"},
                "username": {"type": "keyword"},
                "auth_method": {"type": "keyword"},
                "failure_reason": {"type": "keyword"},
                "session_id": {"type": "keyword"},
                "attack_pattern": {"type": "keyword"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }


def run_elasticsearch_output(config: Config):
    """Stream events to Elasticsearch"""


    if config.debug:
        logging.basicConfig(level=logging.DEBUG)
        for name in ("elasticsearch", "elastic_transport", "urllib3"):
            logging.getLogger(name).setLevel(logging.DEBUG)
        print("[DEBUG] Elasticsearch/transport logging enabled")

    es = Elasticsearch(
        config.es_host,
        basic_auth=(config.es_user, config.es_password),
        verify_certs=config.verify_certs
    )

    # Create index if it doesn't exist
    if not es.indices.exists(index=config.es_index):
        print(f"Creating index: {config.es_index}")
        es.indices.create(index=config.es_index, body=create_index_mapping())

    # Generate and bulk index
    def event_actions():
        for event in generate_events(config):
            yield {
                "_index": config.es_index,
                "_source": event.to_dict()
            }

    print(f"Starting generation: {config.total_events} events at {config.events_per_second}/sec")
    try:
        success, errors = helpers.bulk(es, event_actions(), stats_only=True)
        print(f"Completed: {success} indexed, {errors} errors")
    except BulkIndexError as e:
        if config.debug:
            print("\n[DEBUG] Bulk index errors (why documents failed):")
            for i, err in enumerate(e.errors[:20]):
                print(f"  {i + 1}: {err}")
            if len(e.errors) > 20:
                print(f"  ... and {len(e.errors) - 20} more")
        raise


def run_stdout_output(config: Config):
    """Output events to stdout as NDJSON"""
    for event in generate_events(config):
        print(json.dumps(event.to_dict()))
        time.sleep(1 / config.events_per_second)


def run_file_output(config: Config):
    """Output events to file as NDJSON"""
    with open(config.output_file, 'w') as f:
        for i, event in enumerate(generate_events(config)):
            f.write(json.dumps(event.to_dict()) + "\n")
            if (i + 1) % 1000 == 0:
                print(f"Written {i + 1} events...")
    print(f"Completed: {config.total_events} events written to {config.output_file}")


def main():
    parser = argparse.ArgumentParser(description="Security Log Data Generator")
    parser.add_argument("--es-host", required=True, help="Elasticsearch host URL")
    parser.add_argument("--es-user", default="elastic", help="Elasticsearch username")
    parser.add_argument("--es-password", required=True, help="Elasticsearch password")
    parser.add_argument("--es-index", default="hackathon-security-logs", help="Index name")
    parser.add_argument("--no-verify-certs", action="store_true", help="Disable TLS cert verification")
    parser.add_argument("--output", choices=["elasticsearch", "stdout", "file"], default="elasticsearch")
    parser.add_argument("--output-file", default="security-logs.ndjson", help="Output file for file mode")
    parser.add_argument("--total", type=int, default=10000, help="Total events to generate")
    parser.add_argument("--rate", type=float, default=10.0, help="Events per second")
    parser.add_argument("--attack-probability", type=float, default=15.0, help="Attack injection probability (0-100)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging and print bulk index error details")

    args = parser.parse_args()

    config = Config(
        es_host=args.es_host,
        es_user=args.es_user,
        es_password=args.es_password,
        es_index=args.es_index,
        verify_certs=not args.no_verify_certs,
        output_mode=args.output,
        output_file=args.output_file,
        total_events=args.total,
        events_per_second=args.rate,
        attack_probability=args.attack_probability,
        debug=args.debug
    )

    print(f"Configuration:")
    print(f"  Output: {config.output_mode}")
    print(f"  Total events: {config.total_events}")
    print(f"  Rate: {config.events_per_second} events/sec")
    print(f"  Attack probability: {config.attack_probability}%")
    if config.debug:
        print(f"  Debug: enabled")
    print()
    
    if config.output_mode == "elasticsearch":
        run_elasticsearch_output(config)
    elif config.output_mode == "stdout":
        run_stdout_output(config)
    elif config.output_mode == "file":
        run_file_output(config)


if __name__ == "__main__":
    main()