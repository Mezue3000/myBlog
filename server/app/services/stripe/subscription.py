# import dependencies
from app.cores.logging import get_logger
import stripe
from sqlmodel.ext.asyncio.session import AsyncSession
from app.services.stripe.idempotency import DuplicateWebhookEvent, register_webhook_event
from app.services.stripe.sync import sync_subscription_from_stripe
from app.models import BillingAudit
from app.utility.stripe.helpers import get_webhook_event, update_webhook_status, create_billing_audit, handle_subscription_cancellation





# initialize logging
logger = get_logger(__name__)



# subscription-updated stripe webhook handler
async def handle_subscription_updated(
    *,
    event: dict,
    db: AsyncSession
) -> None:
    """
    Handle Stripe customer.subscription.updated webhook.

    Responsibilities
    ----------------
    1. Register webhook event.
    2. Handle duplicate events correctly.
    3. Synchronize subscription state.
    4. Create billing audit.
    5. Mark webhook as processed.
    6. Commit the transaction.

    Stripe API calls are not required because Stripe sends the
    complete Subscription object in this event.
    """
    
    # validate event id
    event_id = event.get("id")

    if not event_id:
        raise ValueError("Stripe event ID is missing.")

    # register webhook
    try:
        await register_webhook_event(event=event, db=db)

    except DuplicateWebhookEvent:
        logger.info("Stripe webhook '%s' already registered.", event_id)
        
        # determine whether the previous attempt succeeded
        webhook = await get_webhook_event(event_id=event_id, db=db)

        if webhook is None:
            raise RuntimeError(
                f"Webhook '{event_id}' was reported as "
                "duplicate but could not be found."
            )

        # already successfully processed
        if webhook.processed:
            logger.info("Stripe webhook '%s' was already processed.", event_id)

            return

        # previously registered but failed, continue processing instead of ignoring it.
        logger.warning(
            "Retrying previously failed Stripe webhook '%s'. "
            "Previous retry count: %s",
            event_id,
            webhook.retry_count
        )

    # process webhook
    try:
        stripe_subscription = (
            event.get("data", {})
            .get("object")
        )

        if not stripe_subscription:
            raise ValueError("Stripe subscription payload is missing.")

        # synchronize subscription
        tenant, subscription = (
            await sync_subscription_from_stripe(stripe_subscription=stripe_subscription, db=db)
        )

        # create billing audit
        await create_billing_audit(
            tenant_id=tenant.tenant_id,
            stripe_event_id=event["id"],
            event_type=event["type"],
            db=db
        )
        
        await db.flush()

        # mark webhook successfully processed
        await update_webhook_status(
            event_id=event_id,
            processed=True,
            db=db
        )

        # commit
        await db.commit()
        
        logger.info("Successfully processed Stripe event '%s'.", event_id)

    except Exception as exc:
        logger.exception("Failed processing Stripe event '%s'.", event_id)

        # roll back business transaction
        await db.rollback()

        # persist failure state
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
                "Failed to record processing failure "
                "for Stripe event '%s'.",
                event_id
            )

        raise






# subscription-deleted webhook handler
async def handle_subscription_deleted(
    *,
    event: dict,
    db: AsyncSession
) -> None:
    """
    Handle customer.subscription.deleted.

    Flow
    ----
    1. Register webhook for idempotency.
    2. Validate Stripe subscription payload.
    3. Synchronize local subscription.
    4. Apply cancellation business rules.
    5. Create billing audit.
    6. Mark webhook as processed.
    7. Commit.

    On failure:
    - Roll back business changes.
    - Persist processed=False and the error.
    - Commit the failure state separately.
    """

    event_id = event.get("id")

    if not event_id:
        raise ValueError("Stripe event ID missing.")

    try:
        
        # register webhook
        try:
            await register_webhook_event(event=event, db=db)

        except DuplicateWebhookEvent:
            logger.info("Ignoring duplicate Stripe event '%s'.", event_id)

            return

        # validate event payload
        event_data = event.get("data")

        if not isinstance(event_data, dict):
            raise ValueError("Invalid Stripe event data.")

        stripe_subscription = event_data.get("object")

        if not isinstance(stripe_subscription, dict):
            raise ValueError("Invalid Stripe subscription payload.")

        subscription_id = stripe_subscription.get("id")
        customer_id = stripe_subscription.get("customer")

        if not subscription_id:
            raise ValueError("Stripe subscription ID missing.")


        if not customer_id:
            raise ValueError("Stripe customer ID missing.")

        # synchronize local subscription
        tenant, subscription = (
            await sync_subscription_from_stripe(
                stripe_subscription=stripe_subscription,
                db=db
            )
        )

        # apply cancellation business rules
        await handle_subscription_cancellation(
            tenant=tenant,
            subscription=subscription,
            stripe_subscription=stripe_subscription,
            db=db
        )

        # create billing audit
        await create_billing_audit(
            tenant_id=tenant.tenant_id,
            stripe_event_id=event_id,
            event_type=event["type"],
            reference_id=subscription_id,
            description="Stripe subscription deleted.",
            db=db
        )

        # mark webhook successfully processed
        await update_webhook_status(
            event_id=event_id,
            processed=True,
            error=None,
            db=db
        )

        # commit successful transaction
        await db.commit()

        logger.info(
            "Successfully processed "
            "customer.subscription.deleted '%s'.",
            subscription_id
        )

    except Exception as exc:
        
        # roll back business transaction
        await db.rollback()

        logger.exception(
            "Failed processing "
            "customer.subscription.deleted '%s'.",
            event_id
        )

        # persist failure state separately
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
                "Failed to record processing failure "
                "for Stripe event '%s'.",
                event_id
            )

        raise
