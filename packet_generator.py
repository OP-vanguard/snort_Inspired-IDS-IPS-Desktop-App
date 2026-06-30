import os
import random
import time
import math
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap

# --- CONFIGURATION ---
TOTAL_PACKETS = 15000
TOTAL_THREATS = 150  # ~1% threat ratio
TARGET_PCAP = "high_precision_test.pcap"

class UltimateTrafficGenerator:
    def __init__(self):
        self.packets = []
        self.internal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        self.external_ips = [f"203.0.113.{i}" for i in range(1, 255)]
        self.current_time = time.time()

    def _get_ephemeral(self):
        return random.randint(49152, 65535)

    def _build_baseline(self):
        """Generates clean, realistic traffic that will NOT trigger alerts."""
        src = random.choice(self.internal_ips)
        dst = random.choice(self.external_ips)
        choice = random.choices(['http', 'https', 'dns'], weights=[40, 40, 20])[0]

        if choice == 'http':
            # Safe HTTP: No '1=1' or '../' sequences
            payload = "GET /images/logo.png HTTP/1.1\r\nHost: mycompany.com\r\nAccept: image/webp\r\n\r\n"
            return IP(src=src, dst=dst)/TCP(sport=self._get_ephemeral(), dport=80, flags="PA")/Raw(load=payload)
        
        elif choice == 'https':
            # Standard TLS-style binary headers (safe from keyword matches)
            tls_data = b"\x17\x03\x03\x00\x28" + b"\x00"*32 
            return IP(src=src, dst=dst)/TCP(sport=self._get_ephemeral(), dport=443, flags="PA")/Raw(load=tls_data)
        
        elif choice == 'dns':
            return IP(src=src, dst="8.8.8.8")/UDP(sport=self._get_ephemeral(), dport=53)/DNS(rd=1, qd=DNSQR(qname="workplace.com"))

    def _build_threat(self, threat_type):
        """Generates precise attacks mapped to Snort rules."""
        attacker = random.choice(self.external_ips)
        victim = random.choice(self.internal_ips)
        
        if threat_type == "XMAS":
            # Rule SCAN-004: FIN+PSH+URG (0x29)
            return IP(src=attacker, dst=victim)/TCP(sport=self._get_ephemeral(), dport=22, flags="FPU")
        
        elif threat_type == "NULL":
            # Rule SCAN-002: No flags (0x00)
            return IP(src=attacker, dst=victim)/TCP(sport=self._get_ephemeral(), dport=23, flags="")
        
        elif threat_type == "SQLI":
            # Rule WEB-001: SQL Keywords
            payload = "GET /login.php?user=admin' OR '1'='1' -- HTTP/1.1\r\nHost: target.local\r\n\r\n"
            return IP(src=attacker, dst=victim)/TCP(sport=self._get_ephemeral(), dport=80, flags="PA")/Raw(load=payload)
        
        elif threat_type == "DIR_TRAV":
            # Rule WEB-003: Path traversal
            payload = "GET /download.php?file=../../../../etc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n"
            return IP(src=attacker, dst=victim)/TCP(sport=self._get_ephemeral(), dport=80, flags="PA")/Raw(load=payload)
        
        elif threat_type == "PING_FLOOD":
            # Rule SCAN-005: ICMP Echo Request
            return IP(src=attacker, dst=victim)/ICMP(type=8)
        
        elif threat_type == "SYN_FIN":
            # Rule ANOM-001: SYN+FIN (0x03)
            return IP(src=attacker, dst=victim)/TCP(sport=self._get_ephemeral(), dport=80, flags="SF")
        
        elif threat_type == "DGA":
            # Rule MALW-001: High entropy DNS
            dga_domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=18)) + ".com"
            return IP(src=victim, dst="8.8.8.8")/UDP(sport=self._get_ephemeral(), dport=53)/DNS(rd=1, qd=DNSQR(qname=dga_domain))
        
        elif threat_type == "SYN_SCAN":
            # Rule SCAN-001: SYN only to restricted ports
            return IP(src=attacker, dst=victim)/TCP(sport=self._get_ephemeral(), dport=random.choice([21, 23, 25, 110, 139]), flags="S")

    def run(self):
        print(f"[*] Generating {TOTAL_PACKETS} packets...")
        threat_pool = ["XMAS", "NULL", "SQLI", "DIR_TRAV", "PING_FLOOD", "SYN_FIN", "DGA", "SYN_SCAN"]
        
        # Calculate exactly when to drop threats to stay at ~1%
        threat_indices = set(random.sample(range(TOTAL_PACKETS), TOTAL_THREATS))

        for i in range(TOTAL_PACKETS):
            if i in threat_indices:
                t_type = random.choice(threat_pool)
                pkt = self._build_threat(t_type)
            else:
                pkt = self._build_baseline()

            # Increment time realistically (milliseconds)
            self.current_time += random.uniform(0.001, 0.01)
            pkt.time = self.current_time
            self.packets.append(pkt)

            if i % 3000 == 0 and i > 0:
                print(f"    -> {i} packets processed...")

        print(f"[*] Saving to {TARGET_PCAP}...")
        wrpcap(TARGET_PCAP, self.packets)
        print("[+] Success. Traffic ready for analysis.")

if __name__ == "__main__":
    UltimateTrafficGenerator().run()
