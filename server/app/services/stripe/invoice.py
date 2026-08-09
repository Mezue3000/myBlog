# import dependencies
from app.cores.logging import get_logger
import stripe
from sqlmodel.ext.asyncio.session import AsyncSession
from app.services.stripe.idempotency import DuplicateWebhookEvent, register_webhook_event
from app.utility.stripe.helpers import get_webhook_event, update_webhook_status, retrieve_stripe_subscription, create_billing_audit
from app.services.stripe.sync import sync_subscription_from_stripe
from app.services.stripe.credit import allocate_invoice_credits





# initialize logging
logger = get_logger(__name__)



# invoice-paid webhook handler
async def handle_invoice_paid(
    *,
    event: dict,
    db: AsyncSession
) -> None:
    """
    Handle Stripe invoice.paid webhook.

    Responsibilities
    ----------------
    1. Register webhook event for idempotency.
    2. Ignore successfully processed duplicates.
    3. Retry previously failed events.
    4. Validate the Stripe invoice.
    5. Resolve the related subscription.
    6. Synchronize the local subscription.
    7. Allocate the plan's credits.
    8. Create billing audit.
    9. Mark webhook as successfully processed.
    10. Commit the business transaction.

    Stripe API
    ----------
    invoice.paid does not necessarily contain the complete
    Subscription object required by our synchronization logic,
    so the related Stripe Subscription is retrieved when necessary.
    """

    # validate event
    event_id = event.get("id")
    event_type = event.get("type")

    if not event_id:
        raise ValueError("Stripe event ID is missing.")

    if event_type != "invoice.paid":
        raise ValueError(
            f"Invalid event type '{event_type}'. "
            "Expected 'invoice.paid'."
        )

    # register webhook
    try:
        await register_webhook_event(event=event, db=db)

    except DuplicateWebhookEvent:
        logger.info("Stripe webhook '%s' already registered.", event_id)
        webhook = await get_webhook_event(event_id=event_id, db=db)

        if webhook is None:
            raise RuntimeError(
                f"Webhook '{event_id}' was reported as "
                "duplicate but could not be found."
            )

        # already successfully processed
        if webhook.processed:
            logger.info("Stripe webhook '%s' already processed.", event_id)

            return

        # Previously registered but failed, continue processing.
        logger.warning(
            "Retrying previously failed invoice.paid "
            "event '%s'. Retry count=%s.",
            event_id,
            webhook.retry_count
        )

    # process invoice
    try:
        invoice = (
            event.get("data", {})
            .get("object")
        )

        if not invoice:
            raise ValueError("Stripe invoice payload is missing.")

        # validate invoice status
        invoice_id = invoice.get("id")

        if not invoice_id:
            raise ValueError("Stripe invoice ID is missing.")

        invoice_status = invoice.get("status")

        if invoice_status != "paid":
            raise ValueError(
                f"invoice.paid received for invoice "
                f"'{invoice_id}' with status "
                f"'{invoice_status}'."
            )

        # resolve stripe customer
        customer_id = invoice.get("customer")

        if not customer_id:
            raise ValueError(f"Invoice '{invoice_id}' has no Stripe customer."
            )

        # resolve Stripe subscription
        subscription_id = invoice.get("subscription")

        if not subscription_id:
            raise ValueError(
                f"Invoice '{invoice_id}' is not associated "
                "with a Stripe subscription."
            )

        # retrieve complete stripe Subscription
        stripe_subscription = await retrieve_stripe_subscription(subscription_id=subscription_id)
        
        # synchronize local subscription
        tenant, subscription = (
            await sync_subscription_from_stripe(stripe_subscription=stripe_subscription, db=db)
        )

        # verify customer belongs to tenant
        if tenant.stripe_customer_id != customer_id:
            raise ValueError(
                f"Stripe customer mismatch for invoice "
                f"'{invoice_id}'."
            )

        # allocate credits
        await allocate_invoice_credits(
            tenant=tenant,
            subscription=subscription,
            invoice_id=invoice_id,
            db=db
        )

        # create billing audit
        await create_billing_audit(
            tenant_id=tenant.tenant_id,
            stripe_event_id=event_id,
            event_type=event_type,
            db=db
        )
        
        # mark webhook processed
        await update_webhook_status(
            event_id=event_id,
            processed=True,
            db=db
        )

        # commit entire business transaction
        await db.commit()

        logger.info(
            "Successfully processed invoice.paid "
            "event '%s' for invoice '%s'.",
            event_id,
            invoice_id
        )

    except Exception as exc:
        logger.exception("Failed processing invoice.paid event '%s'.", event_id)

        # roll back business transaction
        await db.rollback()
        
        # persist webhook failure
        try:
            await update_webhook_status(
                event_id=event_id,
                processed=False,
                error=exc,
                db=db
            )

            await db.commit()

        except Exception:
            await db.rollback()
            logger.exception(
                "Failed recording invoice.paid failure "
                "for webhook '%s'.",
                event_id
            )

        raise
