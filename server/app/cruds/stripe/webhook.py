# import dependencies
from app.cores.logging import get_logger
import stripe, os
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.billings.helpers import dispatch_webhook





# initialize logging
logger = get_logger(__name__)



# initialize router
router = APIRouter(prefix="/stripe", tags=["Stripe"])



WEBHOOK_SECRET=os.getenv("STRIPE_WEBHOOK_SECRET")



# webhook endpoint
@router.post("/webhook", status_code=status.HTTP_200_OK)
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Stripe webhook endpoint.

    Responsibilities
    ----------------
    1. Read raw payload.
    2. Verify Stripe signature.
    3. Dispatch event.
    """

    payload = await request.body()

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty webhook payload."
        )

    signature = request.headers.get("Stripe-Signature")

    if signature is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Stripe signature."
        )

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=signature,
            secret=WEBHOOK_SECRET
        )

    except ValueError:
        logger.warning("Invalid Stripe webhook payload.")

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook payload."
        )

    except stripe.error.SignatureVerificationError:
        logger.warning("Invalid Stripe webhook signature.")

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Stripe signature."
        )

    await dispatch_webhook(event=event, db=db)

    return {"received": True}
