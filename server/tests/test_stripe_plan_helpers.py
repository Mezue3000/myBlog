# import dependencies
import pytest, stripe
from decimal import Decimal
from app.models import Plan, Tenant, Subscription, StripeCheckoutSession
from app.utility.stripe.helpers import get_active_plan, ensure_plan_compatible_with_tenant, ensure_no_active_subscription, expire_open_checkout_sessions
from sqlmodel import select
from unittest.mock import patch




# test active plan returns plan
@pytest.mark.asyncio
async def test_get_active_plan_returns_active_plan(db):

    plan = Plan(
        name="Active Pro",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("19.99"),
        credits=1000,
        currency="usd",
        features={},
        stripe_price_id="price_test_active_pro",
        description="Active Pro test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    result = await get_active_plan(plan_id=plan.plan_id, db=db) 

    assert result is not None
    assert result.plan_id == plan.plan_id
    assert result.name == "Active Pro"
    assert result.is_active is True



# test plan not exist raises value-error
@pytest.mark.asyncio
async def test_get_active_plan_raises_when_plan_does_not_exist(db):

    with pytest.raises(
        ValueError,
        match="Plan not found.",
    ):
        await get_active_plan(
            plan_id=999999,
            db=db
        )




# test shows plan inactive raises error
@pytest.mark.asyncio
async def test_get_active_plan_raises_when_plan_is_inactive(db):

    plan = Plan(
        name="Inactive Pro",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("19.99"),
        credits=1000,
        currency="usd",
        features={},
        stripe_price_id="price_test_inactive_pro",
        description="Inactive Pro test plan",
        is_active=False
    )

    db.add(plan)
    await db.flush()

    with pytest.raises(ValueError, match="Plan not found."):
        await get_active_plan(plan_id=plan.plan_id, db=db)
        
        
        

# ensure compatible tenant plan allowa compatible plan               
@pytest.mark.asyncio
async def test_ensure_plan_compatible_with_tenant_allows_compatible_plan():

    tenant = Tenant(
        name="Personal Tenant",
        type="personal",
        slug="compatible-personal-tenant",
        plan_id=1
    )

    plan = Plan(
        name="Personal Pro",
        billing_interval="month",
        tenant_type="personal",
        stripe_price_id="price_test_compatible"
    )

    result = await ensure_plan_compatible_with_tenant(
        tenant=tenant,
        plan=plan
    )

    assert result is None

    
    
    
# test to reject incompatible plan
@pytest.mark.asyncio
async def test_ensure_plan_compatible_with_tenant_rejects_incompatible_plan():

    tenant = Tenant(
        name="Personal Tenant",
        type="personal",
        slug="incompatible-personal-tenant",
        plan_id=1
    )

    plan = Plan(
        name="Team Pro",
        billing_interval="month",
        tenant_type="team",
        stripe_price_id="price_test_incompatible"
    )

    with pytest.raises(
        ValueError,
        match="This Team Pro plan is only available for team workspaces."
    ):
        await ensure_plan_compatible_with_tenant(
            tenant=tenant,
            plan=plan
        )



# ensures no active subscription with tenant without sub
@pytest.mark.asyncio
async def test_ensure_no_active_subscription_allows_tenant_without_subscription(
    db
):
    plan = Plan(
        name="Subscription Check Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_no_subscription",
        description="Subscription check plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="No Subscription Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="no-subscription-tenant"
    )

    db.add(tenant)
    await db.flush()

    result = await ensure_no_active_subscription(
        tenant=tenant,
        db=db
    )

    assert result is None
    
    
    
    
# active
@pytest.mark.asyncio
async def test_ensure_no_active_subscription_rejects_active_subscription(
    db
):
    plan = Plan(
        name="Active Subscription Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_active_subscription",
        description="Active subscription test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Active Subscription Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="active-subscription-tenant"
    )

    db.add(tenant)
    await db.flush()

    subscription = Subscription(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_subscription_id="sub_test_active",
        stripe_customer_id="cus_test_active",
        status="active"
    )

    db.add(subscription)
    await db.flush()

    with pytest.raises(
        ValueError,
        match="Tenant already has an active subscription.",
    ):
        await ensure_no_active_subscription(
            tenant=tenant,
            db=db
        )
        
        
        
        
# trailing      
@pytest.mark.asyncio
async def test_ensure_no_active_subscription_rejects_trialing_subscription(
    db
):
    plan = Plan(
        name="Trialing Subscription Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_trialing_subscription",
        description="Trialing subscription test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Trialing Subscription Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="trialing-subscription-tenant"
    )

    db.add(tenant)
    await db.flush()

    subscription = Subscription(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_subscription_id="sub_test_trialing",
        stripe_customer_id="cus_test_trialing",
        status="trialing"
    )

    db.add(subscription)
    await db.flush()

    with pytest.raises(
        ValueError,
        match="Tenant already has an active subscription.",
    ):
        await ensure_no_active_subscription(
            tenant=tenant,
            db=db
        )
        
        
        
        
        
# past due        
@pytest.mark.asyncio
async def test_ensure_no_active_subscription_rejects_past_due_subscription(
    db,
):
    plan = Plan(
        name="Past Due Subscription Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_past_due_subscription",
        description="Past due subscription test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Past Due Subscription Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="past-due-subscription-tenant"
    )

    db.add(tenant)
    await db.flush()

    subscription = Subscription(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_subscription_id="sub_test_past_due",
        stripe_customer_id="cus_test_past_due",
        status="past_due"
    )

    db.add(subscription)
    await db.flush()

    with pytest.raises(
        ValueError,
        match="Tenant already has an active subscription.",
    ):
        await ensure_no_active_subscription(
            tenant=tenant,
            db=db
        )
        
        
        
        
        
# cancelled sub
@pytest.mark.asyncio
async def test_ensure_no_active_subscription_allows_canceled_subscription(
    db
):
    plan = Plan(
        name="Canceled Subscription Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_canceled_subscription",
        description="Canceled subscription test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Canceled Subscription Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="canceled-subscription-tenant"
    )

    db.add(tenant)
    await db.flush()

    subscription = Subscription(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_subscription_id="sub_test_canceled",
        stripe_customer_id="cus_test_canceled",
        status="canceled"
    )

    db.add(subscription)
    await db.flush()

    result = await ensure_no_active_subscription(
        tenant=tenant,
        db=db
    )

    assert result is None
    
    
    



@pytest.mark.asyncio
async def test_expire_open_checkout_sessions_no_open_sessions(
    db,
):
    plan = Plan(
        name="No Open Checkout Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_no_open_checkout",
        description="No open checkout test plan",
        is_active=True,
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="No Open Checkout Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="no-open-checkout-tenant",
    )

    db.add(tenant)
    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.checkout.Session.expire"
    ) as mock_expire:

        result = await expire_open_checkout_sessions(
            tenant=tenant,
            db=db,
        )

        assert result is None
        mock_expire.assert_not_called()
        
        
        
        

@pytest.mark.asyncio
async def test_expire_open_checkout_session(
    db,
):
    plan = Plan(
        name="Open Checkout Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_open_checkout",
        description="Open checkout test plan",
        is_active=True,
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Open Checkout Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="open-checkout-tenant",
    )

    db.add(tenant)
    await db.flush()

    checkout = StripeCheckoutSession(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_test_123",
        stripe_customer_id="cus_test_123",
        status="open",
        payment_status="unpaid",
    )

    db.add(checkout)
    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.checkout.Session.expire"
    ) as mock_expire:

        await expire_open_checkout_sessions(
            tenant=tenant,
            db=db,
        )

        mock_expire.assert_called_once_with(
            "cs_test_123"
        )

    await db.refresh(checkout)

    assert checkout.status == "expired"
    
    
    
    
@pytest.mark.asyncio
async def test_expire_multiple_open_checkout_sessions(
    db,
):
    plan = Plan(
        name="Multiple Checkout Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_multiple_checkout",
        description="Multiple checkout test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Multiple Checkout Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="multiple-checkout-tenant"
    )

    db.add(tenant)
    await db.flush()

    checkout_1 = StripeCheckoutSession(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_test_001",
        stripe_customer_id="cus_test_123",
        status="open",
        payment_status="unpaid"
    )

    checkout_2 = StripeCheckoutSession(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_test_002",
        stripe_customer_id="cus_test_123",
        status="open",
        payment_status="unpaid"
    )

    db.add(checkout_1)
    db.add(checkout_2)
    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.checkout.Session.expire"
    ) as mock_expire:

        await expire_open_checkout_sessions(
            tenant=tenant,
            db=db
        )

        assert mock_expire.call_count == 2

        mock_expire.assert_any_call("cs_test_001")
        mock_expire.assert_any_call("cs_test_002")

    await db.refresh(checkout_1)
    await db.refresh(checkout_2)

    assert checkout_1.status == "expired"
    assert checkout_2.status == "expired"
    




@pytest.mark.asyncio
async def test_expire_open_checkout_sessions_continues_after_stripe_error(
    db,
):
    plan = Plan(
        name="Stripe Error Checkout Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_stripe_error_checkout",
        description="Stripe error checkout test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Stripe Error Checkout Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="stripe-error-checkout-tenant"
    )

    db.add(tenant)
    await db.flush()

    checkout_1 = StripeCheckoutSession(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_test_failure",
        stripe_customer_id="cus_test_123",
        status="open",
        payment_status="unpaid"
    )

    checkout_2 = StripeCheckoutSession(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_test_success",
        stripe_customer_id="cus_test_123",
        status="open",
        payment_status="unpaid"
    )

    db.add(checkout_1)
    db.add(checkout_2)
    await db.flush()

    def expire_side_effect(session_id):
        if session_id == "cs_test_failure":
            raise stripe.error.StripeError(
                "Stripe expiration failed"
            )

        return {
            "id": session_id,
            "status": "expired"
        }

    with patch(
        "app.utility.stripe.helpers.stripe.checkout.Session.expire",
        side_effect=expire_side_effect
    ) as mock_expire:

        result = await expire_open_checkout_sessions(
            tenant=tenant,
            db=db
        )

        assert result is None
        assert mock_expire.call_count == 2

    await db.refresh(checkout_1)
    await db.refresh(checkout_2)

    assert checkout_1.status == "open"
    assert checkout_2.status == "expired"
    
    
    
    
@pytest.mark.asyncio
async def test_expire_open_checkout_sessions_flush_failure(
    db,
):
    plan = Plan(
        name="Flush Failure Checkout Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_flush_failure_checkout",
        description="Flush failure checkout test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Flush Failure Checkout Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="flush-failure-checkout-tenant"
    )

    db.add(tenant)
    await db.flush()

    checkout = StripeCheckoutSession(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_test_flush_failure",
        stripe_customer_id="cus_test_123",
        status="open",
        payment_status="unpaid"
    )

    db.add(checkout)
    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.checkout.Session.expire"
    ) as mock_expire:

        mock_expire.return_value = {
            "id": "cs_test_flush_failure",
            "status": "expired"
        }

        with patch.object(
            db,
            "flush",
            side_effect=RuntimeError("flush failed"),
        ):
            with pytest.raises(
                RuntimeError,
                match="flush failed"
            ):
                await expire_open_checkout_sessions(
                    tenant=tenant,
                    db=db
                )

        mock_expire.assert_called_once_with(
            "cs_test_flush_failure"
        )
        




@pytest.mark.asyncio
async def test_expire_open_checkout_sessions_does_not_expire_another_tenant_session(
    db,
):
    plan = Plan(
        name="Tenant Isolation Checkout Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_tenant_isolation_checkout",
        description="Tenant isolation checkout test plan",
        is_active=True,
    )

    db.add(plan)
    await db.flush()

    tenant_1 = Tenant(
        name="Checkout Tenant One",
        type="personal",
        plan_id=plan.plan_id,
        slug="checkout-tenant-one",
    )

    tenant_2 = Tenant(
        name="Checkout Tenant Two",
        type="personal",
        plan_id=plan.plan_id,
        slug="checkout-tenant-two",
    )

    db.add(tenant_1)
    db.add(tenant_2)
    await db.flush()

    checkout_1 = StripeCheckoutSession(
        tenant_id=tenant_1.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_test_tenant_one",
        stripe_customer_id="cus_test_123",
        status="open",
        payment_status="unpaid",
    )

    checkout_2 = StripeCheckoutSession(
        tenant_id=tenant_2.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_test_tenant_two",
        stripe_customer_id="cus_test_456",
        status="open",
        payment_status="unpaid",
    )

    db.add(checkout_1)
    db.add(checkout_2)
    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.checkout.Session.expire"
    ) as mock_expire:

        await expire_open_checkout_sessions(
            tenant=tenant_1,
            db=db,
        )

        mock_expire.assert_called_once_with(
            "cs_test_tenant_one"
        )

    await db.refresh(checkout_1)
    await db.refresh(checkout_2)

    assert checkout_1.status == "expired"
    assert checkout_2.status == "open"
    
