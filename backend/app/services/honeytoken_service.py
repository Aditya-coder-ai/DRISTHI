"""Service for Honeytoken Generation, Rotation, Revocation, and Event Pipeline Integration."""

import hashlib
import secrets
import string
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.core.exceptions import CrossTenantAccessDeniedException
from backend.app.core.logging import logger
from backend.app.models.honeytoken import Honeytoken
from backend.app.models.asset import DeceptiveAsset
from backend.app.schemas.honeytoken import (
    HoneytokenCreate,
    HoneytokenGenerateRequest,
    HoneytokenStatus,
    HoneytokenType,
    HoneytokenTriggerRequest,
)
from backend.app.services.ingestion_service import IngestionService


class HoneytokenService:
    """Manages full lifecycle of deceptive honeytokens with tenant isolation."""

    def __init__(self, db: Session, tenant_id: str):
        self.db = db
        self.tenant_id = tenant_id.strip()

    @staticmethod
    def hash_token(secret: str) -> str:
        """Computes deterministic SHA-256 hash for secure token lookup."""
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    @staticmethod
    def mask_token(raw: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
        """Masks sensitive secret string."""
        if not raw:
            return "****"
        if len(raw) <= (prefix_len + suffix_len):
            return "****" + raw[-2:]
        return f"{raw[:prefix_len]}****{raw[-suffix_len:]}"

    @classmethod
    def generate_credentials(cls, token_type: str, name: str) -> Tuple[Dict[str, Any], str, str]:
        """
        Generates non-functional, distinguishable decoy credentials.
        Returns:
            Tuple of (raw_credentials_dict, primary_secret_for_hash, masked_representation)
        """
        token_type = token_type.lower()
        clean_name = name.lower().replace(" ", "_")

        if token_type == HoneytokenType.AWS_IAM.value:
            # Canary AWS access key & secret
            rand_suffix = secrets.token_hex(6).upper()
            access_key_id = f"AKIA-CANARY-{rand_suffix}"
            secret_key = f"wJalrXUtnFEMI/K7MDENG/bPxRfiCY{secrets.token_urlsafe(12)}"
            raw_creds = {
                "access_key_id": access_key_id,
                "secret_access_key": secret_key,
                "region": "us-east-1",
                "arn": f"arn:aws:iam::123456789012:user/canary-{clean_name}",
            }
            masked = f"{access_key_id[:12]}****-{access_key_id[-4:]}"
            return raw_creds, access_key_id, masked

        elif token_type == HoneytokenType.SSH_CREDENTIAL.value:
            # Fake SSH canary credentials
            canary_user = f"canary_{clean_name}_{secrets.token_hex(2)}"
            canary_pass = f"Drishti#Canary#{secrets.token_hex(4)}!"
            fake_pubkey = (
                f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC{secrets.token_urlsafe(32)} "
                f"{canary_user}@drishti.internal"
            )
            raw_creds = {
                "username": canary_user,
                "password": canary_pass,
                "public_key": fake_pubkey,
                "auth_type": "password_and_key",
            }
            masked = f"{canary_user}:****"
            return raw_creds, canary_pass, masked

        elif token_type == HoneytokenType.DATABASE_CREDENTIAL.value:
            # Fake Database connection credentials
            db_user = f"db_canary_{clean_name}"
            db_pass = f"DrishtiDb#{secrets.token_hex(6)}"
            conn_str = f"postgresql://{db_user}:{db_pass}@db-cluster.corp.internal:5432/{clean_name}_db"
            raw_creds = {
                "username": db_user,
                "password": db_pass,
                "database": f"{clean_name}_db",
                "host": "db-cluster.corp.internal",
                "port": 5432,
                "connection_string": conn_str,
            }
            masked = f"postgresql://{db_user}:****@db-cluster.corp.internal:5432/{clean_name}_db"
            return raw_creds, db_pass, masked

        elif token_type == HoneytokenType.API_TOKEN.value:
            # Canary API Bearer token
            rand_token = secrets.token_hex(16)
            full_token = f"drishti_canary_live_{rand_token}"
            raw_creds = {
                "token": full_token,
                "token_type": "Bearer",
                "header": f"Authorization: Bearer {full_token}",
            }
            masked = f"drishti_canary_****_{rand_token[-4:]}"
            return raw_creds, full_token, masked

        else:
            # Generic custom token
            rand_val = secrets.token_urlsafe(24)
            full_token = f"custom_canary_{rand_val}"
            raw_creds = {"token": full_token}
            masked = cls.mask_token(full_token)
            return raw_creds, full_token, masked

    def register_honeytoken(self, payload: HoneytokenCreate) -> Tuple[Honeytoken, Optional[Dict[str, Any]]]:
        """Registers a honeytoken under the authenticated tenant with asset registry association."""
        # 1. Enforce tenant isolation on creation
        if payload.tenant_id and payload.tenant_id.strip() != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Unauthorized: cannot register honeytoken under foreign tenant '{payload.tenant_id}'"
            )

        # 2. Validate that parent deceptive asset exists and belongs to this tenant
        asset = self.db.query(DeceptiveAsset).filter(
            DeceptiveAsset.asset_id == payload.asset_id.strip()
        ).first()
        if not asset:
            raise ValueError(f"Deceptive asset '{payload.asset_id}' does not exist in registry")
        if asset.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Asset '{payload.asset_id}' belongs to another tenant. Cannot bind honeytoken."
            )

        # 3. Determine token ID
        token_id = payload.token_id.strip() if payload.token_id else f"htk-{uuid.uuid4().hex[:12]}"
        existing = self.db.query(Honeytoken).filter(Honeytoken.token_id == token_id).first()
        if existing:
            if existing.tenant_id != self.tenant_id:
                raise CrossTenantAccessDeniedException(
                    f"Token ID '{token_id}' is already registered under another tenant"
                )
            raise ValueError(f"Honeytoken with ID '{token_id}' already exists in tenant '{self.tenant_id}'")

        # 4. Handle token secrets
        raw_creds = None
        if payload.token_value:
            secret = payload.token_value.strip()
            token_hash = self.hash_token(secret)
            masked = self.mask_token(secret)
            raw_creds = {"token_value": secret}
        else:
            raw_creds, secret, masked = self.generate_credentials(payload.token_type, payload.name)
            token_hash = self.hash_token(secret)

        now = datetime.now(timezone.utc)
        honeytoken = Honeytoken(
            token_id=token_id,
            tenant_id=self.tenant_id,
            asset_id=payload.asset_id.strip(),
            token_type=payload.token_type.strip().lower(),
            name=payload.name.strip(),
            description=payload.description.strip() if payload.description else None,
            token_value_masked=masked,
            token_hash=token_hash,
            status=payload.status.strip().lower() if payload.status else HoneytokenStatus.ACTIVE.value,
            token_metadata=payload.metadata or {},
            trigger_count=0,
            expires_at=payload.expires_at,
            created_at=now,
            updated_at=now,
        )

        self.db.add(honeytoken)
        self.db.commit()
        self.db.refresh(honeytoken)
        return honeytoken, raw_creds

    def generate_honeytoken(self, request: HoneytokenGenerateRequest) -> Tuple[Honeytoken, Dict[str, Any]]:
        """Generates believable fake credentials, registers them, and returns raw secret once."""
        raw_creds, secret, masked = self.generate_credentials(request.token_type, request.name)
        token_hash = self.hash_token(secret)

        # Validate asset association
        asset = self.db.query(DeceptiveAsset).filter(
            DeceptiveAsset.asset_id == request.asset_id.strip()
        ).first()
        if not asset:
            raise ValueError(f"Deceptive asset '{request.asset_id}' does not exist in registry")
        if asset.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Asset '{request.asset_id}' belongs to another tenant. Cannot generate honeytoken."
            )

        token_id = f"htk-{request.token_type[:3]}-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc)
        expires_at = None
        if request.expires_in_days:
            expires_at = now + timedelta(days=request.expires_in_days)

        honeytoken = Honeytoken(
            token_id=token_id,
            tenant_id=self.tenant_id,
            asset_id=request.asset_id.strip(),
            token_type=request.token_type.strip().lower(),
            name=request.name.strip(),
            description=request.description.strip() if request.description else None,
            token_value_masked=masked,
            token_hash=token_hash,
            status=HoneytokenStatus.ACTIVE.value,
            token_metadata=request.metadata or {},
            trigger_count=0,
            expires_at=expires_at,
            created_at=now,
            updated_at=now,
        )

        self.db.add(honeytoken)
        self.db.commit()
        self.db.refresh(honeytoken)
        return honeytoken, raw_creds

    def rotate_honeytoken(self, token_id: str) -> Tuple[Honeytoken, Honeytoken, Dict[str, Any]]:
        """
        Rotates an existing honeytoken:
        1. Revokes the existing token.
        2. Generates a new active token with same type & asset association.
        3. Returns (old_revoked_token, new_active_token, new_raw_credentials).
        """
        token = self.get_honeytoken(token_id)
        if not token:
            raise ValueError(f"Honeytoken '{token_id}' not found")

        # 1. Generate new replacement token
        raw_creds, secret, masked = self.generate_credentials(token.token_type, f"{token.name} (Rotated)")
        token_hash = self.hash_token(secret)
        new_token_id = f"htk-{token.token_type[:3]}-{uuid.uuid4().hex[:10]}"

        now = datetime.now(timezone.utc)
        new_token = Honeytoken(
            token_id=new_token_id,
            tenant_id=self.tenant_id,
            asset_id=token.asset_id,
            token_type=token.token_type,
            name=f"{token.name} (Rotated)",
            description=token.description,
            token_value_masked=masked,
            token_hash=token_hash,
            status=HoneytokenStatus.ACTIVE.value,
            token_metadata={**(token.token_metadata or {}), "rotated_from": token.token_id},
            trigger_count=0,
            expires_at=token.expires_at,
            created_at=now,
            updated_at=now,
        )

        # 2. Revoke old token
        token.status = HoneytokenStatus.REVOKED.value
        old_meta = dict(token.token_metadata or {})
        old_meta["rotated_to"] = new_token_id
        old_meta["rotated_at"] = now.isoformat()
        token.token_metadata = old_meta
        token.updated_at = now

        self.db.add(new_token)
        self.db.commit()
        self.db.refresh(token)
        self.db.refresh(new_token)

        logger.info(
            "Rotated honeytoken %s -> %s for tenant %s",
            token.token_id, new_token.token_id, self.tenant_id
        )
        return token, new_token, raw_creds

    def revoke_honeytoken(self, token_id: str) -> Honeytoken:
        """Revokes a honeytoken so it cannot be triggered without raising critical alarm."""
        token = self.get_honeytoken(token_id)
        if not token:
            raise ValueError(f"Honeytoken '{token_id}' not found")

        now = datetime.now(timezone.utc)
        token.status = HoneytokenStatus.REVOKED.value
        meta = dict(token.token_metadata or {})
        meta["revoked_at"] = now.isoformat()
        token.token_metadata = meta
        token.updated_at = now

        self.db.commit()
        self.db.refresh(token)
        logger.info("Revoked honeytoken %s for tenant %s", token.token_id, self.tenant_id)
        return token

    def trigger_honeytoken(
        self, token_id: str, trigger_req: HoneytokenTriggerRequest
    ) -> Tuple[Honeytoken, Dict[str, Any]]:
        """
        Records a trigger for a honeytoken and emits a normalized security event
        into the central IngestionService pipeline.
        """
        token = self.get_honeytoken(token_id)
        if not token:
            raise ValueError(f"Honeytoken '{token_id}' not found")

        now = datetime.now(timezone.utc)
        # Dispatch normalized security event into central ingestion pipeline
        event_id = str(uuid.uuid4())
        raw_event = {
            "event_id": event_id,
            "tenant_id": token.tenant_id,
            "asset_id": token.asset_id,
            "honeytoken_id": token.token_id,
            "event_type": "canary_triggered",
            "trigger_type": trigger_req.trigger_type,
            "severity": "critical",
            "source_ip": trigger_req.source_ip,
            "source_port": trigger_req.source_port,
            "source_service": trigger_req.source_service or "honeytoken",
            "username": trigger_req.username,
            "status": "detected",
            "timestamp": now.isoformat(),
            "metadata": {
                "honeytoken_id": token.token_id,
                "honeytoken_name": token.name,
                "token_type": token.token_type,
                "token_value_masked": token.token_value_masked,
                "canary_triggered": True,
                "trigger_type": trigger_req.trigger_type,
                **(trigger_req.details or {}),
            },
        }

        ingestion = IngestionService(self.db)
        resp = ingestion.ingest_payload(raw_event)
        self.db.refresh(token)

        logger.info(
            "Honeytoken %s triggered by %s. Event pipeline status: %s",
            token.token_id, trigger_req.source_ip, resp.status
        )
        return token, raw_event

    def get_honeytoken(self, token_id: str) -> Optional[Honeytoken]:
        """Fetch token by ID, checking expiration and rejecting cross-tenant attempts."""
        clean_id = token_id.strip()
        token = self.db.query(Honeytoken).filter(Honeytoken.token_id == clean_id).first()
        if not token:
            return None
        if token.tenant_id != self.tenant_id:
            raise CrossTenantAccessDeniedException(
                f"Access denied: honeytoken '{clean_id}' belongs to tenant '{token.tenant_id}', not '{self.tenant_id}'"
            )

        # Check expiration dynamically (handling offset-naive/aware datetimes)
        if token.status == HoneytokenStatus.ACTIVE.value and token.expires_at:
            now = datetime.now(timezone.utc)
            exp = token.expires_at if token.expires_at.tzinfo else token.expires_at.replace(tzinfo=timezone.utc)
            if exp <= now:
                token.status = HoneytokenStatus.EXPIRED.value
                token.updated_at = now
                self.db.commit()
                self.db.refresh(token)

        return token
