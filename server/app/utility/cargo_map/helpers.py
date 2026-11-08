# import dependencies
from app.cores.logging import get_logger
from app.models import CargoMessage, CargoRequest
from sqlalchemy import select, update, or_
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4





# initialize logger
logger = get_logger(__name__)



# function to retrieve conversation history
async def get_cargo_conversation(
    *,
    tenant_id: UUID,
    request_id: UUID,
    db: AsyncSession
) -> list[CargoMessage]:

    try:
        statement = (
            select(CargoMessage)
            .where(
                CargoMessage.tenant_id == tenant_id,
                CargoMessage.request_id == request_id
            )
            .order_by(CargoMessage.sequence_number.asc())
        )

        result = await db.execute(statement)

        messages = result.scalars().all()

        logger.info(
            "Cargo conversation retrieved",
            extra={
                "tenant_id": tenant_id,
                "request_id": request_id,
                "message_count": len(messages)
            }
        )

        return list(messages)

    except Exception:
        logger.exception(
            "Failed to retrieve cargo conversation",
            extra={
                "tenant_id": tenant_id,
                "request_id": request_id
            }
        )

        raise
    
    
    
    

# function to persist individual messages
async def save_cargo_message(
    *,
    tenant_id: UUID,
    request_id: UUID,
    role: str,
    content: str,
    db: AsyncSession,
    idempotency_key: Optional[str] = None,
    message_metadata: Optional[dict] = None
) -> CargoMessage:

    try:

        # check for an existing message when an idempotency key is supplied
        if idempotency_key:

            statement = (
                select(CargoMessage)
                .where(
                    CargoMessage.tenant_id == tenant_id,
                    CargoMessage.request_id == request_id,
                    CargoMessage.idempotency_key == idempotency_key
                )
            )

            result = await db.execute(statement)

            existing_message = result.scalar_one_or_none()

            if existing_message:
                return existing_message

        # atomically allocate the next sequence number
        statement = (
            update(CargoRequest)
            .where(
                CargoRequest.tenant_id == tenant_id,
                CargoRequest.request_id == request_id
            )
            .values(
                next_message_sequence=(
                    CargoRequest.next_message_sequence + 1
                )
            )
            .returning(
                CargoRequest.next_message_sequence
            )
        )

        result = await db.execute(statement)

        next_sequence = result.scalar_one_or_none()

        if next_sequence is None:
            raise ValueError(
                "Cargo request not found"
            )

        sequence_number = next_sequence - 1

        # create the message
        message = CargoMessage(
            tenant_id=tenant_id,
            request_id=request_id,
            role=role,
            content=content,
            sequence_number=sequence_number,
            idempotency_key=idempotency_key,
            message_metadata=message_metadata or {}
        )

        # persist the message
        db.add(message)
        await db.flush()

        logger.info(
            "Cargo message saved",
            extra={
                "tenant_id": tenant_id,
                "request_id": request_id,
                "role": role,
                "sequence_number": sequence_number
            }
        )

        return message

    except Exception:

        logger.exception(
            "Failed to save cargo message",
            extra={
                "tenant_id": tenant_id,
                "request_id": request_id,
                "role": role
            }
        )

        raise
    
    
    
    

# function to prevent concurrent processing
async def acquire_request_lease(
    *,
    tenant_id: UUID,
    request_id: UUID,
    db: AsyncSession,
    lease_duration: int = 120
) -> Optional[str]:

    try:

        now = datetime.now(timezone.utc)

        lease_token = str(uuid4())

        expires_at = now + timedelta(seconds=lease_duration)

        statement = (
            update(CargoRequest)
            .where(
                CargoRequest.tenant_id == tenant_id,
                CargoRequest.request_id == request_id,

                or_(
                    CargoRequest.processing_lease_token.is_(None),
                    CargoRequest.processing_lease_expires_at <= now
                )
            )
            .values(
                processing_lease_token=lease_token,
                processing_started_at=now,
                processing_lease_expires_at=expires_at
            )
            .returning(CargoRequest.request_id)
        )

        result = await db.execute(statement)

        acquired = result.scalar_one_or_none()

        if acquired is None:

            logger.warning(
                "Cargo request is already being processed",
                extra={
                    "tenant_id": tenant_id,
                    "request_id": request_id
                }
            )

            return None

        logger.info(
            "Cargo request processing lease acquired",
            extra={
                "tenant_id": tenant_id,
                "request_id": request_id,
                "lease_token": lease_token
            }
        )

        return lease_token

    except Exception:

        logger.exception(
            "Failed to acquire cargo request lease",
            extra={
                "tenant_id": tenant_id,
                "request_id": request_id
            }
        )

        raise





# function to release concurrency hold
async def release_request_lease(
    *,
    tenant_id: UUID,
    request_id: UUID,
    lease_token: str,
    db: AsyncSession
) -> bool:

    try:

        statement = (
            update(CargoRequest)
            .where(
                CargoRequest.tenant_id == tenant_id,
                CargoRequest.request_id == request_id,
                CargoRequest.processing_lease_token == lease_token
            )
            .values(
                processing_lease_token=None,
                processing_lease_expires_at=None,
                processing_started_at=None
            )
            .returning(CargoRequest.request_id)
        )

        result = await db.execute(statement)

        released = result.scalar_one_or_none()

        if released is None:

            logger.warning(
                "Cargo request lease could not be released",
                extra={
                    "tenant_id": tenant_id,
                    "request_id": request_id
                }
            )

            return False

        logger.info(
            "Cargo request processing lease released",
            extra={
                "tenant_id": tenant_id,
                "request_id": request_id
            }
        )

        return True

    except Exception:

        logger.exception(
            "Failed to release cargo request lease",
            extra={
                "tenant_id": tenant_id,
                "request_id": request_id
            }
        )

        raise
