"""Evidence-based MITRE ATT&CK Mapping Engine for DRISTHI."""

from typing import Any, Dict, List
from backend.app.schemas.event import AttackEventCreate, MitreMappingItem


class MitreService:
    """Evaluates attack events against behavioral heuristics to assign evidence-backed MITRE ATT&CK techniques."""

    @classmethod
    def classify_event(cls, event: AttackEventCreate) -> List[MitreMappingItem]:
        mappings: List[MitreMappingItem] = []
        event_type = event.event_type.lower()
        activity = event.activity or {}
        metadata = event.metadata or {}
        service = event.source_service.lower()
        command = str(activity.get("command") or metadata.get("command") or "").lower()

        # 1. T1110.001 - Password Guessing
        if event_type in ("login_failed", "login_attempt") and event.status == "failed":
            user_str = f" for username '{event.username}'" if event.username else ""
            mappings.append(
                MitreMappingItem(
                    technique_id="T1110.001",
                    technique_name="Brute Force: Password Guessing",
                    tactic="Credential Access",
                    confidence=0.90,
                    evidence=f"Observed authentication failure on {event.source_service.upper()}{user_str} from IP {event.source_ip}",
                )
            )

        # 2. T1078 - Valid Accounts (Bait credential trigger or successful honeypot login)
        if event_type in ("bait_credential_trigger", "canary_triggered", "login_success") or metadata.get("bait_credential_triggered"):
            user_str = f" with bait identity '{event.username}'" if event.username else ""
            mappings.append(
                MitreMappingItem(
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                    tactic="Initial Access / Defense Evasion",
                    confidence=0.95,
                    evidence=f"Adversary logged in using deployed bait credential account{user_str} on {event.asset_id}",
                )
            )

        # 3. T1059.004 - Command and Scripting Interpreter: Unix Shell
        if event_type == "command_execution" or command:
            mappings.append(
                MitreMappingItem(
                    technique_id="T1059.004",
                    technique_name="Command and Scripting Interpreter: Unix Shell",
                    tactic="Execution",
                    confidence=0.95,
                    evidence=f"Simulated Linux shell received command: '{command}' from {event.source_ip}",
                )
            )

        # 4. T1082 - System Information Discovery
        if any(sc in command for sc in ("uname", "hostname", "whoami", "id", "cat /etc/issue", "cat /etc/os-release")):
            mappings.append(
                MitreMappingItem(
                    technique_id="T1082",
                    technique_name="System Information Discovery",
                    tactic="Discovery",
                    confidence=0.90,
                    evidence=f"Attacker executed host reconnaissance command '{command}'",
                )
            )

        # 5. T1083 - File and Directory Discovery
        if event_type in ("file_access", "database_enumeration") or any(dc in command for dc in ("ls", "dir", "find", "cat /etc/passwd")):
            mappings.append(
                MitreMappingItem(
                    technique_id="T1083",
                    technique_name="File and Directory Discovery",
                    tactic="Discovery",
                    confidence=0.85,
                    evidence=f"Attacker explored directory structure or file assets: action={event_type}, detail={command or activity.get('path', '/')}",
                )
            )

        # 6. T1048 - Exfiltration Over Alternative Protocol
        if event_type == "file_download":
            path_str = activity.get("path") or activity.get("filename") or "decoy_file"
            mappings.append(
                MitreMappingItem(
                    technique_id="T1048",
                    technique_name="Exfiltration Over Alternative Protocol",
                    tactic="Exfiltration",
                    confidence=0.85,
                    evidence=f"Attacker downloaded bait asset '{path_str}' via {event.source_service.upper()}",
                )
            )

        # 7. T1046 - Network Service Discovery / Web Reconnaissance
        if event_type == "suspicious_request":
            reason = activity.get("reason") or metadata.get("reason") or "Probing unrecognized paths"
            mappings.append(
                MitreMappingItem(
                    technique_id="T1046",
                    technique_name="Network Service Discovery",
                    tactic="Discovery",
                    confidence=0.85,
                    evidence=f"Suspicious probing or directory traversal attempt detected: {reason}",
                )
            )

        # 8. T1021.004 - Remote Services: SSH
        if service == "ssh" and event_type in ("session_connect", "login_attempt"):
            mappings.append(
                MitreMappingItem(
                    technique_id="T1021.004",
                    technique_name="Remote Services: SSH",
                    tactic="Lateral Movement",
                    confidence=0.80,
                    evidence=f"Incoming network connection to SSH service port {event.source_port or 2222} from {event.source_ip}",
                )
            )

        return mappings

