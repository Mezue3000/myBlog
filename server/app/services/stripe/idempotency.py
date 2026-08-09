# import dependencies
from app.cores.logging import get_logger
from app.models import WebhookEvent
from sqlmodel.ext.asyncio.session import AsyncSession
import stripe, json
from sqlalchemy.exc import IntegrityError





# initialize logging
logger = get_logger(__name__)



 # raised when stripe sends an event that has already been registered
class DuplicateWebhookEvent(Exception):
    pass



# function to register stripe webhook
async def register_webhook_event(
    *,
    event: dict,
    db: AsyncSession
) -> None:
    """
    Permanently register a Stripe webhook event.

    This function establishes the idempotency boundary.

    The webhook event is committed before any business logic
    begins. Therefore, if business processing later fails, the
    registration remains in the database.

    The Stripe event ID is unique, so the database provides the
    final protection against concurrent duplicate deliveries.
    """

    event_id = event.get("id")
    event_type = event.get("type")

    if not event_id:
        raise ValueError("Stripe event ID is missing.")

    if not event_type:
        raise ValueError("Stripe event type is missing.")

    webhook = WebhookEvent(
        stripe_event_id=event_id,
        event_type=event_type,
        payload=json.dumps(event),
        processed=False
    )

    db.add(webhook)

    try:
        await db.commit()

    except IntegrityError as exc:
        await db.rollback()
        logger.info("Stripe webhook '%s' has already been registered.", event_id)

        raise DuplicateWebhookEvent from exc

    logger.info("Registered Stripe webhook '%s' (%s).", event_id, event_type)
