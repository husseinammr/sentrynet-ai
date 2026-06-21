"""
data/generate_dataset.py
Generates a realistic Zeek conn.log-style CSV dataset for testing.
Usage: python generate_dataset.py --rows 5000 --out zeek_conn.csv
"""
import csv
import random
import argparse
from datetime import datetime, timedelta


MALICIOUS = ['185.220.101.45', '45.155.205.233', '198.199.70.42']
INTERNAL  = [f'192.168.{r}.{h}' for r in range(1, 4) for h in range(2, 30)]
PORTS     = [80, 443, 22, 21, 25, 53, 3389, 8080, 3306, 5432]
PROTOS    = ['tcp', 'tcp', 'tcp', 'udp', 'icmp']
STATES    = ['SF', 'SF', 'SF', 'S0', 'REJ', 'RSTO', 'OTH']
SERVICES  = {80:'http',443:'https',22:'ssh',21:'ftp',25:'smtp',53:'dns',3389:'rdp',8080:'http-alt',3306:'mysql',5432:'postgresql'}

ATTACKS = [
    {'type':'DDoS',        'pct':0.05},
    {'type':'Port Scan',   'pct':0.05},
    {'type':'Brute Force', 'pct':0.04},
    {'type':'Normal',      'pct':0.86},
]


def rand_public():
    while True:
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        parts = list(map(int, ip.split('.')))
        if parts[0] not in (10, 127, 172, 192) and parts[0] < 224:
            return ip


def gen_row(ts: datetime, attack_type: str) -> dict:
    src = random.choice(INTERNAL)
    dst = rand_public()
    proto = random.choice(PROTOS)

    if attack_type == 'DDoS':
        src      = random.choice(MALICIOUS)
        proto    = 'udp'
        port     = random.choice([80, 443, 53])
        bytes_   = random.randint(10000, 100000)
        packets  = random.randint(500, 5000)
        duration = round(random.uniform(0.001, 0.1), 5)
        state    = 'S0'
    elif attack_type == 'Port Scan':
        src      = random.choice(MALICIOUS)
        port     = random.randint(1, 1024)
        bytes_   = random.randint(40, 200)
        packets  = random.randint(1, 3)
        duration = round(random.uniform(0.0001, 0.01), 5)
        state    = random.choice(['S0', 'REJ'])
    elif attack_type == 'Brute Force':
        src      = random.choice(MALICIOUS)
        port     = random.choice([22, 3389, 21])
        bytes_   = random.randint(200, 800)
        packets  = random.randint(3, 10)
        duration = round(random.uniform(0.1, 2.0), 3)
        state    = random.choice(['REJ', 'RSTO'])
    else:  # Normal
        port     = random.choice(PORTS)
        bytes_   = random.randint(100, 15000)
        packets  = random.randint(1, 50)
        duration = round(random.uniform(0.01, 30.0), 3)
        state    = random.choice(STATES)

    return {
        'ts':          ts.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3],
        'src_ip':      src,
        'dst_ip':      dst,
        'src_port':    random.randint(1024, 65535),
        'dst_port':    port,
        'proto':       proto,
        'service':     SERVICES.get(port, '-'),
        'duration':    duration,
        'bytes':       bytes_,
        'packets':     packets,
        'conn_state':  state,
        'label':       attack_type,
        'is_attack':   0 if attack_type == 'Normal' else 1,
    }


def generate(rows: int, out: str):
    print(f"Generating {rows} Zeek-style conn.log entries → {out}")
    ts = datetime.utcnow() - timedelta(hours=6)

    thresholds = []
    cumulative = 0.0
    for a in ATTACKS:
        cumulative += a['pct']
        thresholds.append((cumulative, a['type']))

    fieldnames = ['ts','src_ip','dst_ip','src_port','dst_port','proto',
                  'service','duration','bytes','packets','conn_state','label','is_attack']

    with open(out, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i in range(rows):
            ts += timedelta(seconds=random.uniform(0.1, 2.0))
            r = random.random()
            atype = 'Normal'
            for threshold, label in thresholds:
                if r <= threshold:
                    atype = label
                    break
            writer.writerow(gen_row(ts, atype))

    # Summary
    print(f"✓ Dataset written: {out}")
    print(f"  Expected distribution:")
    for a in ATTACKS:
        print(f"    {a['type']:15s}: ~{int(a['pct']*rows):5d} rows ({a['pct']*100:.0f}%)")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate Zeek conn.log CSV dataset')
    parser.add_argument('--rows', type=int, default=5000, help='Number of rows')
    parser.add_argument('--out',  type=str, default='zeek_conn.csv', help='Output CSV path')
    args = parser.parse_args()
    generate(args.rows, args.out)
