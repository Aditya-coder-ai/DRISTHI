"""Attacker Behavioral Profile Management Service."""

from typing import List, Optional
from sqlalchemy.orm import Session
from backend.app.models.attacker import AttackerProfile
from backend.app.schemas.event import AttackEventCreate, SeverityLevel
from backend.app.utils.timestamps import ensure_utc


SEVERITY_WEIGHTS = {
    SeverityLevel.LOW.value: 1.0,
    SeverityLevel.MEDIUM.value: 3.0,
    SeverityLevel.HIGH.value: 7.0,
    SeverityLevel.CRITICAL.value: 15.0,
}


class AttackerService:
    """Maintains aggregated behavioral intelligence for observed attacker source IPs."""

    def __init__(self, db: Session):
        self.db = db

    def update_attacker_profile(self, event: AttackEventCreate) -> AttackerProfile:
        profile = self.db.query(AttackerProfile).filter(
            AttackerProfile.source_ip == event.source_ip
        ).first()

        command = (event.activity or {}).get("command") or (event.metadata or {}).get("command")
        event_time = ensure_utc(event.timestamp)

        if not profile:
            attacker_id = f"atk-{event.source_ip.replace('.', '-').replace(':', '-')}"
            usernames = [event.username] if event.username else []
            commands = [command] if command else []
            services = [event.source_service] if event.source_service else []
            risk_score = SEVERITY_WEIGHTS.get(event.severity, 1.0)

            profile = AttackerProfile(
                attacker_id=attacker_id,
                source_ip=event.source_ip,
                first_seen=event_time,
                last_seen=event_time,
                total_events=1,
                total_sessions=1,
                highest_severity=event.severity,
                attempted_usernames=usernames,
                attempted_commands=commands,
                services_targeted=services,
                risk_score=risk_score,
            )
            self.db.add(profile)
            self.db.flush()
            return profile

        # Update existing profile
        profile.total_events += 1
        prof_last_seen = ensure_utc(profile.last_seen)
        if event_time > prof_last_seen:
            profile.last_seen = event_time

        # Unique usernames
        usernames = list(profile.attempted_usernames or [])
        if event.username and event.username not in usernames:
            usernames.append(event.username)
            profile.attempted_usernames = usernames

        # Unique commands
        commands = list(profile.attempted_commands or [])
        if command and command not in commands:
            commands.append(command)
            profile.attempted_commands = commands

        # Unique services targeted
        services = list(profile.services_targeted or [])
        if event.source_service and event.source_service not in services:
            services.append(event.source_service)
            profile.services_targeted = services

        # Highest severity comparison
        sev_order = ["low", "medium", "high", "critical"]
        curr_idx = sev_order.index(profile.highest_severity) if profile.highest_severity in sev_order else 0
        new_idx = sev_order.index(event.severity) if event.severity in sev_order else 0
        if new_idx > curr_idx:
            profile.highest_severity = event.severity

        # Increment risk score
        added_risk = SEVERITY_WEIGHTS.get(event.severity, 1.0)
        profile.risk_score = round(profile.risk_score + added_risk, 2)

        return profile
