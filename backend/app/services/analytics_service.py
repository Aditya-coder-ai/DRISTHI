"""Analytics and Dashboard aggregation service."""

from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List
from sqlalchemy import func, desc
from sqlalchemy.orm import Session
from backend.app.models.event import AttackEvent
from backend.app.models.session import AttackerSession
from backend.app.models.attacker import AttackerProfile
from backend.app.schemas.dashboard import (
    DashboardStatsResponse,
    ServiceCountItem,
    UsernameCountItem,
    CommandCountItem,
    TimelineResponse,
    TimelineBucket,
    ServiceActivityResponse,
    ServiceActivityDetail,
)


class AnalyticsService:
    """Calculates live analytical aggregations derived entirely from database records."""

    def __init__(self, db: Session):
        self.db = db

    def get_dashboard_stats(self) -> DashboardStatsResponse:
        total_events = self.db.query(func.count(AttackEvent.event_id)).scalar() or 0
        unique_attackers = self.db.query(func.count(func.distinct(AttackEvent.source_ip))).scalar() or 0
        active_sessions = self.db.query(func.count(AttackerSession.session_id)).filter(
            AttackerSession.status.in_(["active", "escalated"])
        ).scalar() or 0

        # Canary triggers count
        canary_triggers = self.db.query(func.count(AttackEvent.event_id)).filter(
            AttackEvent.event_type.in_(["canary_triggered", "bait_credential_trigger", "credential_reuse"])
        ).scalar() or 0

        # Severity breakdown
        sev_counts = self.db.query(
            AttackEvent.severity, func.count(AttackEvent.event_id)
        ).group_by(AttackEvent.severity).all()
        sev_dict = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for sev, count in sev_counts:
            sev_dict[str(sev).lower()] = count

        # Top targeted services
        svc_counts = self.db.query(
            AttackEvent.source_service, func.count(AttackEvent.event_id)
        ).group_by(AttackEvent.source_service).order_by(desc(func.count(AttackEvent.event_id))).limit(10).all()
        top_services = [ServiceCountItem(service=s, count=c) for s, c in svc_counts]

        # Top attempted usernames
        user_counts = self.db.query(
            AttackEvent.username, func.count(AttackEvent.event_id)
        ).filter(
            AttackEvent.username.isnot(None),
            AttackEvent.username != "",
        ).group_by(AttackEvent.username).order_by(desc(func.count(AttackEvent.event_id))).limit(10).all()
        top_usernames = [UsernameCountItem(username=u, count=c) for u, c in user_counts]

        # Top commands from attacker profiles
        profiles = self.db.query(AttackerProfile).all()
        cmd_counter = Counter()
        for p in profiles:
            cmds = p.attempted_commands or []
            for c in cmds:
                if c:
                    cmd_counter[c] += 1
        top_commands = [CommandCountItem(command=cmd, count=cnt) for cmd, cnt in cmd_counter.most_common(10)]

        return DashboardStatsResponse(
            total_events=total_events,
            unique_attackers=unique_attackers,
            active_sessions=active_sessions,
            canary_triggers=canary_triggers,
            severity_breakdown=sev_dict,
            top_targeted_services=top_services,
            top_usernames=top_usernames,
            top_commands=top_commands,
        )

    def get_timeline(self, hours: int = 24) -> TimelineResponse:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=hours)

        events = self.db.query(
            AttackEvent.timestamp,
            AttackEvent.severity,
        ).filter(
            AttackEvent.timestamp >= start_time
        ).order_by(AttackEvent.timestamp.asc()).all()

        buckets_map: Dict[str, Dict[str, int]] = {}

        for ts, sev in events:
            # Bucket by hour
            bucket_key = ts.strftime("%Y-%m-%dT%H:00:00Z")
            if bucket_key not in buckets_map:
                buckets_map[bucket_key] = {"total": 0, "critical": 0, "high": 0}
            buckets_map[bucket_key]["total"] += 1
            if sev == "critical":
                buckets_map[bucket_key]["critical"] += 1
            elif sev == "high":
                buckets_map[bucket_key]["high"] += 1

        timeline_buckets = [
            TimelineBucket(
                time_bucket=k,
                event_count=v["total"],
                critical_count=v["critical"],
                high_count=v["high"],
            )
            for k, v in sorted(buckets_map.items())
        ]

        return TimelineResponse(
            interval="hour",
            buckets=timeline_buckets,
        )

    def get_services_activity(self) -> ServiceActivityResponse:
        svc_assets = self.db.query(
            AttackEvent.source_service,
            AttackEvent.asset_id,
            func.count(AttackEvent.event_id).label("total_events"),
            func.count(func.distinct(AttackEvent.source_ip)).label("unique_attackers"),
            func.max(AttackEvent.timestamp).label("last_event_time"),
        ).group_by(
            AttackEvent.source_service,
            AttackEvent.asset_id,
        ).all()

        details = []
        active_sessions_records = self.db.query(AttackerSession.services_accessed).filter(
            AttackerSession.status.in_(["active", "escalated"])
        ).all()

        for svc, asset, total, unique_ips, last_time in svc_assets:
            active_sess = sum(
                1 for (services_list,) in active_sessions_records
                if services_list and svc in services_list
            )

            details.append(
                ServiceActivityDetail(
                    service=svc,
                    asset_id=asset,
                    total_events=total,
                    unique_attackers=unique_ips,
                    active_sessions=active_sess,
                    last_event_time=last_time.isoformat() if last_time else "",
                )
            )

        return ServiceActivityResponse(services=details)
