# import dependencies
from app.cores.logging import get_logger
from app.models import WebhookEvent
from sqlmodel.ext.asyncio.session import AsyncSession
import stripe, json
from sqlalchemy.exc import IntegrityError





# initialize logging
logger = get_logger(__name__)



 # raised when Stripe retries an already registered event
class DuplicateWebhookEvent(Exception):
    pass



# function to register stripe webhook
async def register_webhook_event( 
    *,
    event: dict,
    db: AsyncSession
) -> None:
    """
    Register a Stripe webhook.

    Event is permanently recorded before any business
    logic starts/this handles idempotency registration.
    """

    webhook = WebhookEvent(
        stripe_event_id=event["id"],
        event_type=event["type"],
        payload=json.dumps(event)
    )

    db.add(webhook)

    try:
        await db.commit()

    except IntegrityError as exc:
        await db.rollback()
        raise DuplicateWebhookEvent from exc

    logger.info("Registered Stripe webhook %s.", event["id"])
