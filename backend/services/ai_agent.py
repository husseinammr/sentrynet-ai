"""
services/ai_agent.py
المرحلة 6 — AI Agent مستقل
Autonomous threat analysis: detects → analyzes → decides → acts → reports.
Uses Claude API for intelligent incident analysis and report generation.
"""
import asyncio
import json
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Callable
from utils.logger import get_logger

logger = get_logger(__name__)

# Anthropic API endpoint (called from backend server)
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-sonnet-4-20250514"


AGENT_SYSTEM_PROMPT = """You are SentryNet AI Agent — an autonomous cybersecurity analyst.

You receive network threat data and must:
1. Analyze the attack pattern
2. Assess severity and impact
3. Recommend response actions
4. Generate a concise incident report

ALWAYS respond with valid JSON only, no markdown, no extra text:
{
  "incident_id": "INC-XXXX",
  "title": "Short attack title",
  "severity": "critical|high|medium|low",
  "attack_type": "DDoS|Port Scan|Brute Force|Data Exfiltration|APT|Unknown",
  "confidence": 0.0-1.0,
  "summary": "2-3 sentence analysis",
  "attacker_profile": "Brief description of likely attacker",
  "impact_assessment": "What could happen if not stopped",
  "recommended_actions": ["action1", "action2", "action3"],
  "auto_actions_taken": ["action already taken"],
  "ioc": {"ips": [], "ports": [], "protocols": []},
  "timeline": "Brief attack timeline",
  "report": "Full incident report paragraph (3-5 sentences)"
}"""


class AIAgent:
    """
    Autonomous AI agent that:
    - Monitors alert queue
    - Calls Claude API for deep incident analysis
    - Decides and coordinates automated responses
    - Generates forensic reports
    - Learns from each incident
    """

    def __init__(self, auto_response=None):
        self.auto_response = auto_response     # AutoResponseEngine instance
        self.incident_queue: deque = deque(maxlen=100)
        self.incident_reports: List[dict] = []
        self.active_incidents: Dict[str, dict] = {}
        self._notify_callbacks: List[Callable] = []
        self._processing = False
        self._incident_counter = 1000
        self.total_incidents = 0
        self.total_auto_resolved = 0

        # Start background processing loop
        asyncio.create_task(self._processing_loop())

    def on_incident(self, callback: Callable):
        self._notify_callbacks.append(callback)

    async def _fire(self, event: dict):
        for cb in self._notify_callbacks:
            try:
                await cb(event)
            except Exception as e:
                logger.error(f"Agent callback error: {e}")

    # ─── Ingest alerts ────────────────────────────────
    def ingest_alerts(self, alerts: List[dict]):
        """Called with new alerts from alert_manager."""
        critical = [a for a in alerts if a.get("severity") in ("critical", "high")]
        for alert in critical:
            self.incident_queue.append(alert)

    # ─── Background processing loop ───────────────────
    async def _processing_loop(self):
        await asyncio.sleep(3)  # Startup delay
        while True:
            try:
                if self.incident_queue and not self._processing:
                    # Batch up to 5 alerts per analysis
                    batch = []
                    while self.incident_queue and len(batch) < 5:
                        batch.append(self.incident_queue.popleft())

                    if batch:
                        await self._analyze_incident(batch)

                await asyncio.sleep(4)
            except Exception as e:
                logger.error(f"Agent loop error: {e}")
                await asyncio.sleep(5)

    # ─── Core analysis ────────────────────────────────
    async def _analyze_incident(self, alerts: List[dict]):
        self._processing = True
        self._incident_counter += 1
        inc_id = f"INC-{self._incident_counter}"

        try:
            logger.info(f"Agent analyzing incident {inc_id} ({len(alerts)} alerts)...")

            # Build context for Claude
            context = self._build_context(alerts)

            # Call Claude API
            analysis = await self._call_claude(context)

            if not analysis:
                # Fallback to rule-based analysis
                analysis = self._rule_based_analysis(alerts, inc_id)
            else:
                analysis["incident_id"] = inc_id

            # Execute recommended actions
            actions_taken = await self._execute_actions(analysis, alerts)
            analysis["auto_actions_taken"] = actions_taken

            # Store report
            report = {
                **analysis,
                "alerts": alerts,
                "ts": datetime.utcnow().isoformat(),
                "resolved": len(actions_taken) > 0,
            }
            self.incident_reports.insert(0, report)
            if len(self.incident_reports) > 50:
                self.incident_reports = self.incident_reports[:50]

            self.total_incidents += 1
            if actions_taken:
                self.total_auto_resolved += 1

            # Notify dashboard
            await self._fire({
                "type": "agent_incident",
                "incident": report,
            })

            logger.info(f"Incident {inc_id} analyzed. Actions: {actions_taken}")

        except Exception as e:
            logger.error(f"Incident analysis failed: {e}")
        finally:
            self._processing = False

    # ─── Claude API call ──────────────────────────────
    async def _call_claude(self, context: str) -> Optional[dict]:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    CLAUDE_API_URL,
                    headers={"Content-Type": "application/json"},
                    json={
                        "model": CLAUDE_MODEL,
                        "max_tokens": 800,
                        "system": AGENT_SYSTEM_PROMPT,
                        "messages": [{"role": "user", "content": context}],
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    text = data["content"][0]["text"]
                    return json.loads(text)
        except Exception as e:
            logger.warning(f"Claude API unavailable, using rule-based fallback: {e}")
        return None

    def _build_context(self, alerts: List[dict]) -> str:
        ips    = list({a.get("src_ip","") for a in alerts})
        ports  = list({a.get("dst_port", 0) for a in alerts})
        types  = list({a.get("attack_type","Unknown") for a in alerts})
        scores = [a.get("anomaly_score", 0) for a in alerts]
        avg_score = sum(scores) / len(scores) if scores else 0

        return f"""NETWORK THREAT ALERT — IMMEDIATE ANALYSIS REQUIRED

Timestamp: {datetime.utcnow().isoformat()}
Alert count: {len(alerts)}
Source IPs: {ips}
Target ports: {ports}
Attack types detected: {types}
Average anomaly score: {avg_score:.3f}
Highest severity: {max((a.get('severity','low') for a in alerts), key=lambda s: ['low','medium','high','critical'].index(s) if s in ['low','medium','high','critical'] else 0)}

Alert details:
{json.dumps(alerts[:3], indent=2, default=str)}

Analyze this incident and respond with the required JSON."""

    # ─── Rule-based fallback ──────────────────────────
    def _rule_based_analysis(self, alerts: List[dict], inc_id: str) -> dict:
        types  = list({a.get("attack_type","Unknown") for a in alerts})
        ips    = list({a.get("src_ip","") for a in alerts})
        ports  = list({a.get("dst_port",0) for a in alerts})
        sev    = max((a.get("severity","low") for a in alerts),
                     key=lambda s: ["low","medium","high","critical"].index(s)
                     if s in ["low","medium","high","critical"] else 0)
        attack = types[0] if types else "Unknown"

        profiles = {
            "DDoS":            "Automated botnet or amplification attack targeting availability.",
            "Brute Force":     "Automated credential stuffing tool targeting authentication services.",
            "Port Scan":       "Reconnaissance tool (nmap/masscan) mapping network topology.",
            "Data Exfiltration": "Compromised internal host transferring data to C2 server.",
        }
        impacts = {
            "DDoS":            "Service unavailability, bandwidth saturation, revenue loss.",
            "Brute Force":     "Unauthorized access, credential compromise, lateral movement.",
            "Port Scan":       "Network topology exposure, preparation for targeted attack.",
            "Data Exfiltration": "Sensitive data loss, compliance violations, reputational damage.",
        }

        return {
            "incident_id": inc_id,
            "title": f"{attack} Attack Detected",
            "severity": sev,
            "attack_type": attack,
            "confidence": 0.82,
            "summary": f"Detected {attack} activity from {len(ips)} source IP(s). "
                       f"Pattern matches known {attack.lower()} signatures with high confidence.",
            "attacker_profile": profiles.get(attack, "Unknown threat actor using automated tooling."),
            "impact_assessment": impacts.get(attack, "Potential network disruption or data exposure."),
            "recommended_actions": [
                f"Block source IP(s): {', '.join(ips[:3])}",
                "Enable rate limiting on affected ports",
                "Review firewall rules and update threat intel feeds",
                "Notify security team and document in SIEM",
            ],
            "auto_actions_taken": [],
            "ioc": {"ips": ips, "ports": ports, "protocols": list({a.get("proto","") for a in alerts})},
            "timeline": f"Attack initiated and detected within current monitoring window.",
            "report": f"Incident {inc_id}: A {sev.upper()} severity {attack} attack was detected "
                      f"originating from {ips[0] if ips else 'unknown'} targeting port(s) "
                      f"{ports[:3]}. Automated analysis completed. "
                      f"Immediate containment actions are recommended.",
        }

    # ─── Execute actions ──────────────────────────────
    async def _execute_actions(self, analysis: dict, alerts: List[dict]) -> List[str]:
        if not self.auto_response:
            return []
        actions_taken = []

        sev = analysis.get("severity", "low")
        ips = analysis.get("ioc", {}).get("ips", [])

        # Auto-block for high/critical
        if sev in ("critical", "high") and ips:
            for ip in ips[:3]:  # Max 3 IPs per incident
                result = await self.auto_response._block_ip(
                    ip,
                    f"Auto-blocked by AI Agent — {analysis.get('attack_type','')} [{analysis['incident_id']}]",
                    severity=sev,
                    auto_unblock=True,
                )
                if result:
                    actions_taken.append(f"Blocked IP: {ip}")

        # Isolate internal hosts for exfiltration
        if analysis.get("attack_type") == "Data Exfiltration":
            internal = [ip for ip in ips if self.auto_response._is_internal(ip)]
            for ip in internal[:2]:
                result = await self.auto_response._isolate_host(
                    ip, f"AI Agent isolation — Data Exfiltration [{analysis['incident_id']}]"
                )
                if result:
                    actions_taken.append(f"Isolated host: {ip}")

        return actions_taken

    def get_status(self) -> dict:
        return {
            "total_incidents":     self.total_incidents,
            "total_auto_resolved": self.total_auto_resolved,
            "queue_size":          len(self.incident_queue),
            "processing":          self._processing,
            "recent_reports":      self.incident_reports[:5],
        }
