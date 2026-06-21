"""
Traffic Simulator — generates realistic Zeek-style network traffic logs.
In production, replace with actual Zeek log tail/streaming reader.
"""
import random
import time
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict
import math

# Known malicious IPs (simulated threat intel)
MALICIOUS_IPS = [
    "185.220.101.45", "45.155.205.233", "198.199.70.42",
    "192.241.207.82", "104.248.38.10", "165.227.88.15",
]

# Common service ports
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 3389, 8080, 8443, 3306, 5432, 27017]
SCAN_PORTS = list(range(1, 1025))

# GeoIP data (simulated)
GEOIP_DB = {
    "US": ["New York", "Los Angeles", "Chicago", "Houston"],
    "CN": ["Beijing", "Shanghai", "Guangzhou"],
    "RU": ["Moscow", "Saint Petersburg"],
    "DE": ["Berlin", "Hamburg", "Munich"],
    "BR": ["São Paulo", "Rio de Janeiro"],
    "IN": ["Mumbai", "Delhi", "Bangalore"],
    "GB": ["London", "Manchester"],
    "FR": ["Paris", "Lyon"],
    "KR": ["Seoul", "Busan"],
    "JP": ["Tokyo", "Osaka"],
}

COUNTRIES = list(GEOIP_DB.keys())

def random_private_ip():
    subnets = ["192.168.", "10.0.", "10.1.", "172.16."]
    subnet = random.choice(subnets)
    return f"{subnet}{random.randint(1, 254)}.{random.randint(1, 254)}"

def random_public_ip():
    while True:
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        try:
            addr = ipaddress.ip_address(ip)
            if not addr.is_private and not addr.is_loopback:
                return ip
        except Exception:
            continue

def random_geoip():
    country = random.choice(COUNTRIES)
    city = random.choice(GEOIP_DB[country])
    lat_base = {"US": 37, "CN": 35, "RU": 55, "DE": 51, "BR": -15,
                 "IN": 20, "GB": 51, "FR": 46, "KR": 37, "JP": 36}
    lng_base = {"US": -95, "CN": 105, "RU": 37, "DE": 10, "BR": -47,
                 "IN": 77, "GB": -1, "FR": 2, "KR": 128, "JP": 138}
    return {
        "country": country,
        "city": city,
        "lat": lat_base.get(country, 0) + random.uniform(-5, 5),
        "lng": lng_base.get(country, 0) + random.uniform(-5, 5),
    }


class TrafficSimulator:
    def __init__(self):
        self.internal_hosts = [random_private_ip() for _ in range(20)]
        self.packet_counter = 0
        self.attack_mode = False
        self.attack_type = None
        self.attack_source = None
        self.attack_end_time = None
        self._inject_attacks_counter = 0

    def _maybe_start_attack(self):
        """Randomly inject attack scenarios."""
        self._inject_attacks_counter += 1
        # Start an attack every ~60 calls on average
        if not self.attack_mode and random.random() < 0.015:
            self.attack_mode = True
            self.attack_type = random.choice(["ddos", "port_scan", "brute_force"])
            self.attack_source = random.choice(MALICIOUS_IPS + [random_public_ip()])
            self.attack_end_time = time.time() + random.randint(10, 30)

        # End attack
        if self.attack_mode and time.time() > (self.attack_end_time or 0):
            self.attack_mode = False
            self.attack_type = None
            self.attack_source = None

    def _generate_normal_entry(self) -> Dict:
        src_ip = random.choice(self.internal_hosts)
        dst_ip = random_public_ip()
        proto = random.choice(["tcp", "udp", "icmp"])
        port = random.choice(COMMON_PORTS)
        bytes_sent = random.randint(100, 15000)
        packets = random.randint(1, 50)
        duration = round(random.uniform(0.01, 30.0), 3)
        return {
            "ts": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "proto": proto,
            "bytes": bytes_sent,
            "packets": packets,
            "duration": duration,
            "service": self._port_to_service(port),
            "conn_state": random.choice(["SF", "S0", "REJ", "RSTO", "OTH"]),
            "geoip": random_geoip(),
            "attack_type": None,
        }

    def _generate_ddos_entry(self) -> Dict:
        entry = self._generate_normal_entry()
        entry["src_ip"] = self.attack_source
        entry["bytes"] = random.randint(10000, 100000)
        entry["packets"] = random.randint(500, 5000)
        entry["duration"] = round(random.uniform(0.001, 0.1), 4)
        entry["proto"] = "udp"
        entry["attack_type"] = "DDoS"
        return entry

    def _generate_port_scan_entry(self) -> Dict:
        entry = self._generate_normal_entry()
        entry["src_ip"] = self.attack_source
        entry["dst_port"] = random.choice(SCAN_PORTS)
        entry["bytes"] = random.randint(40, 200)
        entry["packets"] = random.randint(1, 3)
        entry["duration"] = round(random.uniform(0.0001, 0.01), 5)
        entry["conn_state"] = random.choice(["S0", "REJ"])
        entry["attack_type"] = "Port Scan"
        return entry

    def _generate_brute_force_entry(self) -> Dict:
        entry = self._generate_normal_entry()
        entry["src_ip"] = self.attack_source
        entry["dst_port"] = random.choice([22, 3389, 21, 5900])
        entry["service"] = self._port_to_service(entry["dst_port"])
        entry["bytes"] = random.randint(200, 800)
        entry["packets"] = random.randint(3, 10)
        entry["conn_state"] = random.choice(["REJ", "RSTO", "S0"])
        entry["attack_type"] = "Brute Force"
        return entry

    def _port_to_service(self, port: int) -> str:
        mapping = {
            80: "http", 443: "https", 22: "ssh", 21: "ftp", 25: "smtp",
            53: "dns", 3389: "rdp", 8080: "http-alt", 8443: "https-alt",
            3306: "mysql", 5432: "postgresql", 27017: "mongodb",
        }
        return mapping.get(port, f"port-{port}")

    def generate_batch(self, size: int = 10) -> List[Dict]:
        self._maybe_start_attack()
        entries = []
        for _ in range(size):
            if self.attack_mode:
                ratio = random.random()
                if self.attack_type == "ddos" and ratio < 0.7:
                    entries.append(self._generate_ddos_entry())
                elif self.attack_type == "port_scan" and ratio < 0.6:
                    entries.append(self._generate_port_scan_entry())
                elif self.attack_type == "brute_force" and ratio < 0.5:
                    entries.append(self._generate_brute_force_entry())
                else:
                    entries.append(self._generate_normal_entry())
            else:
                entries.append(self._generate_normal_entry())
        self.packet_counter += sum(e["packets"] for e in entries)
        return entries
