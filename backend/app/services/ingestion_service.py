"""Central Event Ingestion Pipeline Service."""

from typing import Any, Dict, List, Union
from sqlalchemy.orm import Session
from backend.app.core.logging import logger
from backend.app.integrations.person1_adapter import Person1SecurityEventAdapter
from backend.app.models.event import AttackEvent
from backend.app.models.mitre import MitreMapping
from backend.app.schemas.event import IngestionResponse, AttackEventCreate
from backend.app.services.asset_service import AssetService
from backend.app.services.attacker_service import AttackerService
from backend.app.services.mitre_service import MitreService
from backend.app.services.session_service import SessionService
from backend.app.websocket.manager import ws_manager


class IngestionService:
    """Orchestrates validation, deduplication, session correlation, MITRE mapping, and persistence."""

    def __init__(self, db: Session):
        self.db = db
        self.adapter = Person1SecurityEventAdapter()
        self.asset_service = AssetService(db)
        self.session_service = SessionService(db)
        self.attacker_service = AttackerService(db)

    def ingest_payload(self, payload: Union[Dict[str, Any], List[Dict[str, Any]]]) -> IngestionResponse:
        """Processes a single event or a batch of events with transactional safety."""
        if isinstance(payload, dict):
            raw_events = [payload]
        elif isinstance(payload, list):
            raw_events = payload
        else:
            return IngestionResponse(
                status="failed",
                processed=0,
                persisted=0,
                duplicates_skipped=0,
                errors=["Payload must be an event dictionary or list of event dictionaries"],
            )

        processed = 0
        persisted = 0
        duplicates_skipped = 0
        errors = []

        for raw_item in raw_events:
            processed += 1
            try:
                # 1. Normalize and validate event
                event_create: Optional[AttackEventCreate] = self.adapter.adapt(raw_item)
                if not event_create:
                    errors.append(f"Item #{processed}: Invalid event payload could not be normalized")
                    continue

                # 2. Check for deduplication by event_id
                existing = self.db.query(AttackEvent).filter(
                    AttackEvent.event_id == event_create.event_id
                ).first()
                if existing:
                    duplicates_skipped += 1
                    continue

                # 3. Update or create Attacker Profile
                attacker_profile = self.attacker_service.update_attacker_profile(event_create)

                # 4. Ensure deceptive asset is registered
                self.asset_service.ensure_asset_registered(
                    asset_id=event_create.asset_id,
                    tenant_id=event_create.tenant_id,
                    source_service=event_create.source_service,
                )

                # 5. Correlate or create Attacker Session
                session = self.session_service.get_or_create_session(
                    event_create, attacker_id=attacker_profile.attacker_id
                )
                event_create.session_id = session.session_id

                # 6. Persist Attack Event
                event_model = AttackEvent(
                    event_id=event_create.event_id,
                    tenant_id=event_create.tenant_id,
                    session_id=event_create.session_id,
                    source_ip=event_create.source_ip,
                    source_port=event_create.source_port,
                    source_service=event_create.source_service,
                    asset_id=event_create.asset_id,
                    event_type=event_create.event_type,
                    username=event_create.username,
                    severity=event_create.severity,
                    status=event_create.status,
                    timestamp=event_create.timestamp,
                    activity=event_create.activity,
                    metadata_=event_create.metadata,
                )
                self.db.add(event_model)
                self.db.flush()

                # 6. Apply evidence-based MITRE ATT&CK mappings
                mitre_items = MitreService.classify_event(event_create)
                for m_item in mitre_items:
                    mitre_model = MitreMapping(
                        event_id=event_create.event_id,
                        technique_id=m_item.technique_id,
                        technique_name=m_item.technique_name,
                        tactic=m_item.tactic,
                        confidence=m_item.confidence,
                        evidence=m_item.evidence,
                    )
                    self.db.add(mitre_model)

                persisted += 1

                # 7. Broadcast real-time update
                ws_manager.broadcast_sync({
                    "type": "NEW_EVENT",
                    "data": {
                        "event_id": event_create.event_id,
                        "tenant_id": event_create.tenant_id,
                        "session_id": event_create.session_id,
                        "source_service": event_create.source_service,
                        "asset_id": event_create.asset_id,
                        "source_ip": event_create.source_ip,
                        "event_type": event_create.event_type,
                        "username": event_create.username,
                        "severity": event_create.severity,
                        "timestamp": event_create.timestamp.isoformat(),
                    }
                })

            except Exception as exc:
                logger.error("Error processing event item #%d: %s", processed, exc)
                errors.append(f"Item #{processed}: {str(exc)}")

        # Commit all persisted operations atomically
        try:
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.error("Failed to commit batch ingestion transaction: %s", exc)
            return IngestionResponse(
                status="failed",
                processed=processed,
                persisted=0,
                duplicates_skipped=duplicates_skipped,
                errors=[f"Database transaction commit failed: {str(exc)}"],
            )

        logger.info(
            "Batch ingestion finished: processed=%d, persisted=%d, duplicates_skipped=%d, errors=%d",
            processed, persisted, duplicates_skipped, len(errors)
        )
        return IngestionResponse(
            status="success" if not errors else "partial_success",
            processed=processed,
            persisted=persisted,
            duplicates_skipped=duplicates_skipped,
            errors=errors,
        )

