"""
services/auto_response.py
المرحلة 3 — الاستجابة التلقائية للهجمات
Auto-blocks IPs, isolates infected hosts, sends notifications.
"""
import asyncio
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Callable
from utils.logger import get_logger

logger = get_logger(__name__)


# ─── Thresholds ───────────────────────────────────────
BRUTE_FORCE_THRESHOLD  = 5    # attempts before block
DDOS_PPS_THRESHOLD     = 1000 # packets/sec before block
PORT_SCAN_THRESHOLD    = 20   # distinct ports before block
AUTO_UNBLOCK_SECONDS   = 300  # 5 min auto-unblock


class AutoResponseEngine:
    """
    Monitors enriched traffic entries and takes automated action:
      - Block IPs via iptables (or simulation)
      - Isolate infected LAN hosts
      - Send real-time notifications (WebSocket / Telegram / Slack)
    """

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run          # True = simulate, don't touch OS
        self.blocked_ips: Dict[str, dict] = {}          # ip → {reason, ts, expires}
        self.isolated_hosts: Dict[str, dict] = {}       # ip → {reason, ts}
        self.brute_counters: Dict[str, int] = defaultdict(int)
        self.port_scan_tracker: Dict[str, set] = defaultdict(set)
        self.ddos_pps: Dict[str, int] = defaultdict(int)
        self.action_log: List[dict] = []
        self._notify_callbacks: List[Callable] = []
        self._last_cleanup = time.time()

    # ─── Register notification callbacks ──────────────
    def on_action(self, callback: Callable):
        """Register async callback: called with action dict on every automated response."""
        self._notify_callbacks.append(callback)

    async def _fire(self, action: dict):
        self.action_log.insert(0, action)
        if len(self.action_log) > 200:
            self.action_log = self.action_log[:200]
        for cb in self._notify_callbacks:
            try:
                await cb(action)
            except Exception as e:
                logger.error(f"Notification callback error: {e}")

    # ─── Main entry point ─────────────────────────────
    async def process(self, entries: List[dict]) -> List[dict]:
        """
        Called with each batch of enriched traffic.
        Returns list of automated actions taken.
        """
        self._maybe_cleanup()
        actions = []

        for entry in entries:
            src  = entry.get("src_ip", "")
            attack = entry.get("attack_type")
            severity = entry.get("severity", "low")

            # Skip already-blocked IPs (still record attempt)
            if src in self.blocked_ips:
                continue

            if not entry.get("is_anomaly"):
                continue

            # ── DDoS ──────────────────────────────────
            if attack == "DDoS":
                self.ddos_pps[src] += entry.get("packets", 0)
                if self.ddos_pps[src] >= DDOS_PPS_THRESHOLD:
                    action = await self._block_ip(src, "DDoS flood detected",
                                                   severity="critical",
                                                   auto_unblock=True)
                    if action:
                        actions.append(action)
                        self.ddos_pps[src] = 0

            # ── Brute Force ───────────────────────────
            elif attack == "Brute Force":
                self.brute_counters[src] += 1
                if self.brute_counters[src] >= BRUTE_FORCE_THRESHOLD:
                    action = await self._block_ip(
                        src,
                        f"Brute force on port {entry.get('dst_port')} "
                        f"({self.brute_counters[src]} attempts)",
                        severity="high",
                        auto_unblock=True,
                    )
                    if action:
                        actions.append(action)
                        self.brute_counters[src] = 0

            # ── Port Scan ─────────────────────────────
            elif attack == "Port Scan":
                self.port_scan_tracker[src].add(entry.get("dst_port", 0))
                if len(self.port_scan_tracker[src]) >= PORT_SCAN_THRESHOLD:
                    action = await self._block_ip(
                        src,
                        f"Port scan ({len(self.port_scan_tracker[src])} ports probed)",
                        severity="medium",
                        auto_unblock=True,
                    )
                    if action:
                        actions.append(action)
                        self.port_scan_tracker[src] = set()

            # ── Data Exfiltration (isolate LAN host) ──
            elif attack == "Data Exfiltration":
                if self._is_internal(src):
                    action = await self._isolate_host(src, "Suspected data exfiltration")
                    if action:
                        actions.append(action)
                else:
                    action = await self._block_ip(src, "External exfil source",
                                                   severity="critical")
                    if action:
                        actions.append(action)

        return actions

    # ─── Actions ──────────────────────────────────────
    async def _block_ip(self, ip: str, reason: str,
                        severity: str = "high",
                        auto_unblock: bool = True) -> Optional[dict]:
        if ip in self.blocked_ips:
            return None

        expires = time.time() + AUTO_UNBLOCK_SECONDS if auto_unblock else None
        self.blocked_ips[ip] = {
            "reason": reason, "ts": datetime.utcnow().isoformat(),
            "severity": severity, "expires": expires,
        }

        # Execute firewall rule
        if not self.dry_run:
            self._iptables_block(ip)
        else:
            logger.info(f"[DRY-RUN] iptables -A INPUT -s {ip} -j DROP  # {reason}")

        action = {
            "type": "block_ip",
            "target": ip,
            "reason": reason,
            "severity": severity,
            "ts": datetime.utcnow().isoformat(),
            "auto_unblock_in": AUTO_UNBLOCK_SECONDS if auto_unblock else None,
            "dry_run": self.dry_run,
            "message": f"🚫 IP Blocked: {ip} — {reason}",
        }
        logger.warning(f"AUTO-BLOCK: {ip} | {reason}")
        await self._fire(action)
        return action

    async def _isolate_host(self, ip: str, reason: str) -> Optional[dict]:
        if ip in self.isolated_hosts:
            return None

        self.isolated_hosts[ip] = {
            "reason": reason, "ts": datetime.utcnow().isoformat(),
        }

        if not self.dry_run:
            # Drop all traffic to/from LAN host except management VLAN
            self._iptables_isolate(ip)
        else:
            logger.info(f"[DRY-RUN] ISOLATE HOST {ip}  # {reason}")

        action = {
            "type": "isolate_host",
            "target": ip,
            "reason": reason,
            "severity": "critical",
            "ts": datetime.utcnow().isoformat(),
            "dry_run": self.dry_run,
            "message": f"🔒 Host Isolated: {ip} — {reason}",
        }
        logger.critical(f"AUTO-ISOLATE: {ip} | {reason}")
        await self._fire(action)
        return action

    async def unblock_ip(self, ip: str) -> bool:
        if ip not in self.blocked_ips:
            return False
        del self.blocked_ips[ip]
        if not self.dry_run:
            self._iptables_unblock(ip)
        logger.info(f"UNBLOCKED: {ip}")
        await self._fire({"type": "unblock_ip", "target": ip,
                           "ts": datetime.utcnow().isoformat(),
                           "message": f"✅ IP Unblocked: {ip}"})
        return True

    # ─── Firewall commands ────────────────────────────
    def _iptables_block(self, ip: str):
        try:
            subprocess.run(["iptables", "-A", "INPUT",  "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
        except Exception as e:
            logger.error(f"iptables block failed for {ip}: {e}")

    def _iptables_unblock(self, ip: str):
        try:
            subprocess.run(["iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"])
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        except Exception as e:
            logger.error(f"iptables unblock failed for {ip}: {e}")

    def _iptables_isolate(self, ip: str):
        try:
            subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
            subprocess.run(["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"])
        except Exception as e:
            logger.error(f"iptables isolate failed for {ip}: {e}")

    # ─── Helpers ──────────────────────────────────────
    def _is_internal(self, ip: str) -> bool:
        return ip.startswith(("192.168.", "10.", "172.16.", "172.17.",
                              "172.18.", "172.19.", "172.20."))

    def _maybe_cleanup(self):
        """Auto-unblock expired IPs every 30 seconds."""
        if time.time() - self._last_cleanup < 30:
            return
        self._last_cleanup = time.time()
        now = time.time()
        expired = [ip for ip, info in self.blocked_ips.items()
                   if info.get("expires") and info["expires"] < now]
        for ip in expired:
            asyncio.create_task(self.unblock_ip(ip))

    def get_status(self) -> dict:
        return {
            "blocked_ips":    list(self.blocked_ips.items()),
            "isolated_hosts": list(self.isolated_hosts.items()),
            "total_actions":  len(self.action_log),
            "recent_actions": self.action_log[:10],
            "dry_run":        self.dry_run,
        }
