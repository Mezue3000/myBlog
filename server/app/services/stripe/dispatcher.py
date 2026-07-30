# import dependencies
from app.cores.logging import get_logger
from sqlmodel.ext.asyncio.session import AsyncSession
import stripe





# initialize logging
logger = get_logger(__name__)



# function to route stripe events
EVENT_HANDLERS = {
#     "checkout.session.completed": handle_checkout_completed,
#     "invoice.paid": handle_invoice_paid,
#     "invoice.payment_failed": handle_invoice_payment_failed,
#     "customer.subscription.updated": handle_subscription_updated,
#     "customer.subscription.deleted": handle_subscription_deleted,
}



async def dispatch_webhook(
    *,
    event: stripe.Event,
    db: AsyncSession
) -> None:
    """
    Dispatch a Stripe webhook event to its handler.

    Unsupported events are ignored
    """

    event_id = event["id"]
    event_type = event["type"]

    handler = EVENT_HANDLERS.get(event_type)

    if handler is None:
        logger.info(
            "Ignoring unsupported Stripe event '%s' (%s).",
            event_type,
            event_id
        )
        return

    logger.info(
        "Dispatching Stripe event '%s' (%s).",
        event_type,
        event_id
    )

    try:
        await handler(event=event, db=db)

    except stripe.error.StripeError:
        logger.exception(
            "Stripe SDK error while processing '%s' (%s).",
            event_type,
            event_id
        )
        raise

    except Exception:
        logger.exception(
            "Unexpected error while processing '%s' (%s).",
            event_type,
            event_id
        )
        raise

    logger.info(
        "Successfully processed Stripe event '%s' (%s).",
        event_type,
        event_id
    )
