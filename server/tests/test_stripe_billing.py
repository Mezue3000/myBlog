# import dependencies
import pytest, stripe
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
from app.models import Tenant, Plan, User, StripeCheckoutSession, Role
from app.services.stripe.checkout import create_checkout_session
from sqlmodel import select
from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from tests.conftest import TestSessionLocal
from types import SimpleNamespace




# ensure checkout uses requested plan & tenant
@pytest.mark.asyncio
async def test_create_checkout_session_uses_requested_plan_for_supplied_tenant(
    db
):
    # create two different plans
    plan_a = Plan(
        name="Pro Plan",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("10.00"),
        credits=1000,
        currency="usd",
        features={},
        stripe_price_id="price_pro_monthly",
        description="Pro plan",
        is_active=True
    )

    plan_b = Plan(
        name="Enterprise Plan",
        billing_interval="year",
        tenant_type="personal",
        amount=Decimal("100.00"),
        credits=10000,
        currency="usd",
        features={},
        stripe_price_id="price_enterprise_yearly",
        description="Enterprise plan",
        is_active=True
    )

    db.add(plan_a)
    db.add(plan_b)
    await db.flush()

    # create two different tenants
    tenant_a = Tenant(
        name="Tenant A",
        type="personal",
        plan_id=plan_a.plan_id,
        slug="tenant-a"
    )

    tenant_b = Tenant(
        name="Tenant B",
        type="personal",
        plan_id=plan_b.plan_id,
        slug="tenant-b"
    )

    db.add(tenant_a)
    db.add(tenant_b)
    await db.flush()

    # create the user belonging to Tenant A's context    
    role = Role(name="user")
    
    db.add(role)
    await db.flush()
     
    user = User(
        username="tenant_a_user",
        email="tenant-a@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(user)
    await db.flush()

    # stripe customer belongs to tenant A
    customer_id = "cus_tenant_a"

    # Stripe checkout response
    stripe_session = MagicMock()
    stripe_session.id = "cs_test_tenant_a"
    stripe_session.url = (
        "https://checkout.stripe.com/c/pay/"
        "cs_test_tenant_a"
    )
    stripe_session.customer = customer_id
    stripe_session.status = "open"
    stripe_session.payment_status = "unpaid"
    stripe_session.expires_at = None

    # mock the helper calls that were already tested separately
    with (
        patch(
            "app.services.stripe.checkout.get_active_plan",
            new=AsyncMock(return_value=plan_b),
        ) as mock_get_active_plan,
    
        patch(
            "app.services.stripe.checkout.ensure_plan_compatible_with_tenant",
            new=AsyncMock(),
        ) as mock_ensure_compatible,
    
        patch(
            "app.services.stripe.checkout.ensure_no_active_subscription",
            new=AsyncMock(),
        ) as mock_no_active_subscription,
    
        patch(
            "app.services.stripe.checkout.ensure_stripe_customer",
            new=AsyncMock(return_value=customer_id),
        ) as mock_customer,
    
        patch(
            "app.services.stripe.checkout.expire_open_checkout_sessions",
            new=AsyncMock(),
        ) as mock_expire_checkouts,
    
        patch(
            "app.services.stripe.checkout.to_thread",
            new=AsyncMock(return_value=stripe_session),
        ) as mock_to_thread,
        ):
   

        result = await create_checkout_session(
            tenant=tenant_a,
            current_user=user,
            plan_id=plan_b.plan_id,
            db=db
        )

    # returned value must be Stripe's Checkout URL
    assert result == stripe_session.url

    # requested plan must be Plan B
    mock_get_active_plan.assert_awaited_once_with(
        plan_id=plan_b.plan_id,
        db=db
    )

    mock_ensure_compatible.assert_awaited_once_with(
        tenant=tenant_a,
        plan=plan_b
    )

    # tenant must be tenant A
    mock_customer.assert_awaited_once_with(
        tenant=tenant_a,
        current_user=user,
        db=db
    )

    mock_no_active_subscription.assert_awaited_once_with(tenant=tenant_a, db=db)
    mock_expire_checkouts.assert_awaited_once_with(tenant=tenant_a, db=db)

    # inspect the actual Stripe Checkout arguments
    mock_to_thread.assert_awaited_once()

    args, kwargs = mock_to_thread.await_args

    assert args[0].__name__ == "create"

    assert kwargs["customer"] == customer_id
    assert kwargs["mode"] == "subscription"

    # tenant A, not tenant B
    assert kwargs["client_reference_id"] == str(tenant_a.tenant_id)

    # plan B, not plan A
    assert kwargs["line_items"] == [
        {
            "price": plan_b.stripe_price_id,
            "quantity": 1
        }
    ]

    # verify metadata contains the correct tenant + plan
    assert kwargs["metadata"] == {
        "tenant_id": str(tenant_a.tenant_id),
        "plan_id": plan_b.plan_id,
        "tenant_type": tenant_a.type,
        "billing_interval": plan_b.billing_interval
    }

    # verify local checkout record
    checkout_result = await db.exec(
        select(StripeCheckoutSession).where(
            StripeCheckoutSession.stripe_session_id == stripe_session.id
        )
    )

    checkout = checkout_result.first()

    assert checkout is not None

    assert checkout.tenant_id == tenant_a.tenant_id
    assert checkout.plan_id == plan_b.plan_id
    assert checkout.stripe_session_id == stripe_session.id
    assert checkout.stripe_customer_id == customer_id
    assert checkout.status == "open"
    assert checkout.payment_status == "unpaid"
    
    



# ensure checkout rejects free plan
@pytest.mark.asyncio
async def test_create_checkout_session_rejects_free_plan(
    db: AsyncSession
):
    role = Role(name="user")
    
    db.add(role)
    await db.flush()

    user = User(
        username="free_plan_user",
        email="free-plan@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    
    db.add(user)
    await db.flush()

    plan = Plan(
        name="free",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_free_test"
    )
    
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Free Tenant",
        slug="free-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id
    )
    
    db.add(tenant)
    await db.flush()

    with patch(
        "app.services.stripe.checkout.stripe.checkout.Session.create"
    ) as mock_create:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == ("Free plan does not require stripe checkout.")

    mock_create.assert_not_called()




# ensure create_checkout_seesion rejects plan without stripe price id
@pytest.mark.asyncio
async def test_create_checkout_session_rejects_plan_without_stripe_price(
    db: AsyncSession,
):
    role = Role(name="user")
    db.add(role)
    await db.flush()

    user = User(
        username="missing_price_user",
        email="missing-price@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    db.add(user)
    await db.flush()

    plan = Plan(
        name="pro",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_test_pro"
    )
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Missing Price Tenant",
        slug="missing-price-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id,
    )
    db.add(tenant)
    await db.flush()

    # simulate a loaded plan whose stripe price id is missing.
    plan.stripe_price_id = None

    with patch(
        "app.services.stripe.checkout.get_active_plan",
        new=AsyncMock(return_value=plan),
    ), patch(
        "app.services.stripe.checkout.ensure_plan_compatible_with_tenant",
        new=AsyncMock(),
    ), patch(
        "app.services.stripe.checkout.stripe.checkout.Session.create",
    ) as mock_create:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert exc_info.value.detail == (
        "Stripe price is not configured for this plan."
    )

    mock_create.assert_not_called()





# ensure existing active subscription rejected
@pytest.mark.asyncio
async def test_create_checkout_session_rejects_existing_active_subscription(
    db: AsyncSession
):
    role = Role(name="user")
    db.add(role)
    await db.flush()

    user = User(
        username="active_subscription_user",
        email="active-subscription@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    
    db.add(user)
    await db.flush()

    plan = Plan(
        name="pro",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_test_pro"
    )
    
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Active Subscription Tenant",
        slug="active-subscription-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id
    )
    
    db.add(tenant)
    await db.flush()

    with patch(
        "app.services.stripe.checkout.ensure_no_active_subscription",
        new=AsyncMock(
            side_effect=ValueError(
                "Tenant already has an active subscription."
            )
        ),
    ) as mock_ensure_subscription, patch(
        "app.services.stripe.checkout.ensure_stripe_customer",
        new=AsyncMock(),
    ) as mock_customer, patch(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        new=AsyncMock(),
    ) as mock_expire, patch(
        "app.services.stripe.checkout.to_thread",
        new=AsyncMock(),
    ) as mock_to_thread:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == (
        status.HTTP_500_INTERNAL_SERVER_ERROR
    )
    assert exc_info.value.detail == (
        "Unable to create Checkout session."
    )

    mock_ensure_subscription.assert_awaited_once_with(
        tenant=tenant,
        db=db
    )

    mock_customer.assert_not_awaited()
    mock_expire.assert_not_awaited()
    mock_to_thread.assert_not_awaited()
    

    
    
# ensure stripe customer failure handled
@pytest.mark.asyncio
async def test_create_checkout_session_handles_stripe_customer_failure(
    db: AsyncSession
):
    role = Role(name="user")
    db.add(role)
    await db.flush()

    user = User(
        username="customer_failure_user",
        email="customer-failure@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    
    db.add(user)
    await db.flush()

    plan = Plan(
        name="pro",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_test_pro"
    )
    
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Customer Failure Tenant",
        slug="customer-failure-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id
    )
    
    db.add(tenant)
    await db.flush()

    with patch(
        "app.services.stripe.checkout.ensure_stripe_customer",
        new=AsyncMock(
            side_effect=RuntimeError(
                "Unable to create Stripe customer."
            )
        ),
    ) as mock_customer, patch(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        new=AsyncMock(),
    ) as mock_expire, patch(
        "app.services.stripe.checkout.to_thread",
        new=AsyncMock(),
    ) as mock_to_thread:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == (
        status.HTTP_500_INTERNAL_SERVER_ERROR
    )
    assert exc_info.value.detail == (
        "Unable to create Checkout session."
    )

    mock_customer.assert_awaited_once_with(
        tenant=tenant,
        current_user=user,
        db=db
    )

    mock_expire.assert_not_awaited()
    mock_to_thread.assert_not_awaited()




# ensure previous checkout expiration failure handled
@pytest.mark.asyncio
async def test_create_checkout_session_handles_checkout_expiration_failure(
    db: AsyncSession
):
    role = Role(name="user")
    db.add(role)
    await db.flush()

    user = User(
        username="expiration_failure_user",
        email="expiration-failure@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    
    db.add(user)
    await db.flush()

    plan = Plan(
        name="pro",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_test_pro"
    )
    
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Expiration Failure Tenant",
        slug="expiration-failure-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id
    )
    
    db.add(tenant)
    await db.flush()

    customer_id = "cus_test_expiration_failure"

    with patch(
        "app.services.stripe.checkout.ensure_stripe_customer",
        new=AsyncMock(return_value=customer_id),
    ) as mock_customer, patch(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        new=AsyncMock(
            side_effect=RuntimeError(
                "Unable to expire open checkout sessions."
            )
        ),
    ) as mock_expire, patch(
        "app.services.stripe.checkout.to_thread",
        new=AsyncMock(),
    ) as mock_to_thread:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == (
        status.HTTP_500_INTERNAL_SERVER_ERROR
    )
    assert exc_info.value.detail == (
        "Unable to create Checkout session."
    )

    mock_customer.assert_awaited_once_with(
        tenant=tenant,
        current_user=user,
        db=db
    )

    mock_expire.assert_awaited_once_with(
        tenant=tenant,
        db=db
    )

    mock_to_thread.assert_not_awaited()




# ensure stripe Checkout API failure handled
@pytest.mark.asyncio
async def test_create_checkout_session_handles_stripe_checkout_failure(
    db: AsyncSession,
):
    role = Role(name="user")
    db.add(role)
    await db.flush()

    user = User(
        username="checkout_failure_user",
        email="checkout-failure@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    
    db.add(user)
    await db.flush()

    plan = Plan(
        name="pro",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_test_pro"
    )
    
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Checkout Failure Tenant",
        slug="checkout-failure-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id
    )
    
    db.add(tenant)
    await db.flush()

    customer_id = "cus_test_checkout_failure"

    stripe_error = stripe.error.StripeError(
        "Stripe Checkout creation failed."
    )

    with patch(
        "app.services.stripe.checkout.ensure_stripe_customer",
        new=AsyncMock(return_value=customer_id),
    ), patch(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        new=AsyncMock(),
    ), patch(
        "app.services.stripe.checkout.to_thread",
        new=AsyncMock(side_effect=stripe_error)
    ) as mock_to_thread:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == (
        status.HTTP_400_BAD_REQUEST
    )
    assert exc_info.value.detail == (
        "Unable to create Stripe Checkout session."
    )

    mock_to_thread.assert_awaited_once()
    
    
    
    
# ensure missing stripe session ID rejected    
@pytest.mark.asyncio
async def test_create_checkout_session_rejects_missing_stripe_session_id(
    db: AsyncSession
):
    role = Role(name="user")
    db.add(role)
    await db.flush()

    user = User(
        username="missing_session_id_user",
        email="missing-session-id@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    db.add(user)
    await db.flush()

    plan = Plan(
        name="pro",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_test_pro"
    )
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Missing Session ID Tenant",
        slug="missing-session-id-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id
    )
    db.add(tenant)
    await db.flush()

    customer_id = "cus_test_missing_session_id"

    stripe_session = MagicMock()
    stripe_session.id = None
    stripe_session.url = "https://checkout.stripe.com/test"
    stripe_session.customer = customer_id
    stripe_session.status = "open"
    stripe_session.payment_status = "unpaid"
    stripe_session.expires_at = None

    with patch(
        "app.services.stripe.checkout.ensure_stripe_customer",
        new=AsyncMock(return_value=customer_id),
    ), patch(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        new=AsyncMock(),
    ), patch(
        "app.services.stripe.checkout.to_thread",
        new=AsyncMock(return_value=stripe_session),
    ) as mock_to_thread:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == (
        status.HTTP_500_INTERNAL_SERVER_ERROR
    )
    assert exc_info.value.detail == (
        "Unable to create Checkout session."
    )

    mock_to_thread.assert_awaited_once()




# ensure missing stripe session URL rejected
@pytest.mark.asyncio
async def test_create_checkout_session_rejects_missing_stripe_session_url(
    db: AsyncSession
):
    role = Role(name="user")
    db.add(role)
    await db.flush()

    user = User(
        username="missing_session_url_user",
        email="missing-session-url@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    db.add(user)
    await db.flush()

    plan = Plan(
        name="pro",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_test_pro"
    )
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Missing Session URL Tenant",
        slug="missing-session-url-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id
    )
    db.add(tenant)
    await db.flush()

    customer_id = "cus_test_missing_session_url"

    stripe_session = MagicMock()
    stripe_session.id = "cs_test_missing_url"
    stripe_session.url = None
    stripe_session.customer = customer_id
    stripe_session.status = "open"
    stripe_session.payment_status = "unpaid"
    stripe_session.expires_at = None

    with patch(
        "app.services.stripe.checkout.ensure_stripe_customer",
        new=AsyncMock(return_value=customer_id),
    ), patch(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        new=AsyncMock(),
    ), patch(
        "app.services.stripe.checkout.to_thread",
        new=AsyncMock(return_value=stripe_session),
    ) as mock_to_thread:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == (
        status.HTTP_500_INTERNAL_SERVER_ERROR
    )
    assert exc_info.value.detail == (
        "Unable to create Checkout session."
    )

    mock_to_thread.assert_awaited_once()
    
    
    
    
# ensure stripe customer mismatch rejected
@pytest.mark.asyncio
async def test_create_checkout_session_rejects_customer_mismatch(
    db: AsyncSession
):
    role = Role(name="user")
    db.add(role)
    await db.flush()

    user = User(
        username="customer_mismatch_user",
        email="customer-mismatch@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )
    
    db.add(user)
    await db.flush()

    plan = Plan(
        name="pro",
        tenant_type="personal",
        billing_interval="month",
        is_active=True,
        stripe_price_id="price_test_pro"
    )
    
    db.add(plan)
    await db.flush()

    tenant = Tenant(
        name="Customer Mismatch Tenant",
        slug="customer-mismatch-tenant",
        type="personal",
        plan_id=plan.plan_id,
        owner_id=user.user_id
    )
    
    db.add(tenant)
    await db.flush()

    customer_id = "cus_expected_customer"
    different_customer_id = "cus_different_customer"

    stripe_session = MagicMock()
    stripe_session.id = "cs_test_customer_mismatch"
    stripe_session.url = "https://checkout.stripe.com/customer-mismatch"
    stripe_session.customer = different_customer_id
    stripe_session.status = "open"
    stripe_session.payment_status = "unpaid"
    stripe_session.expires_at = None

    with patch(
        "app.services.stripe.checkout.ensure_stripe_customer",
        new=AsyncMock(return_value=customer_id),
    ), patch(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        new=AsyncMock(),
    ), patch(
        "app.services.stripe.checkout.to_thread",
        new=AsyncMock(return_value=stripe_session),
    ) as mock_to_thread:

        with pytest.raises(HTTPException) as exc_info:
            await create_checkout_session(
                tenant=tenant,
                current_user=user,
                plan_id=plan.plan_id,
                db=db
            )

    assert exc_info.value.status_code == (
        status.HTTP_500_INTERNAL_SERVER_ERROR
    )
    
    assert exc_info.value.detail == (
        "Unable to create Checkout session."
    )

    mock_to_thread.assert_awaited_once()

    checkout_result = await db.exec(
        select(StripeCheckoutSession).where(
            StripeCheckoutSession.stripe_session_id
            == stripe_session.id
        )
    )

    assert checkout_result.first() is None





# ensure local database persistence failure transaction rollback verified
@pytest.mark.asyncio
async def test_create_checkout_session_handles_local_persistence_failure(
    db,
    monkeypatch
):
    # create role
    role = Role(name="user")

    db.add(role)
    await db.flush()

    # create user
    user = User(
        username="tenant_a_user",
        email="tenant-a@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(user)
    await db.flush()

    # create plan
    plan = Plan(
        name="pro",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_pro_test",
        credits=1000
    )

    db.add(plan)
    await db.flush()

    # create tenant
    tenant = Tenant(
        name="Tenant A",
        type="team",
        plan_id=plan.plan_id,
        slug="tenant-a-persistence-failure",
        credits_remaining=100
    )

    db.add(tenant)
    await db.flush()

    # stripe customer already exists
    tenant.stripe_customer_id = "cus_test_123"

    # save scalar IDs before switching sessions
    tenant_id = tenant.tenant_id
    plan_id = plan.plan_id

    # create the existing checkout in a SEPARATE session
    # and commit it so the service rollback cannot remove it.
    existing_checkout_id = None

    async with TestSessionLocal() as setup_db:

        existing_checkout = StripeCheckoutSession(
            tenant_id=tenant_id,
            plan_id=plan_id,
            stripe_session_id="cs_existing_123",
            stripe_customer_id="cus_test_123",
            status="open",
            payment_status="unpaid"
        )

        setup_db.add(existing_checkout)

        await setup_db.commit()

        existing_checkout_id = existing_checkout.checkout_id

    # mock helper functions used by checkout.py
    async def mock_get_active_plan(plan_id, db):
        return plan

    async def mock_ensure_plan_compatible_with_tenant(
        tenant,
        plan
    ):
        return None

    async def mock_ensure_no_active_subscription(
        tenant,
        db
    ):
        return None

    async def mock_ensure_stripe_customer(
        tenant,
        current_user,
        db
    ):
        return "cus_test_123"

    async def mock_expire_open_checkout_sessions(
        tenant,
        db
    ):
        return None

    monkeypatch.setattr(
        "app.services.stripe.checkout.get_active_plan",
        mock_get_active_plan
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_plan_compatible_with_tenant",
        mock_ensure_plan_compatible_with_tenant
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_no_active_subscription",
        mock_ensure_no_active_subscription
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_stripe_customer",
        mock_ensure_stripe_customer
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        mock_expire_open_checkout_sessions
    )

    # mock Stripe Checkout response.
    # it deliberately uses the SAME stripe_session_id
    # as the committed checkout above.
    stripe_session = {
        "id": "cs_existing_123",
        "url": "https://checkout.stripe.com/c/pay/test",
        "customer": "cus_test_123",
        "status": "open",
        "payment_status": "unpaid",
        "expires_at": None
    }

    async def mock_to_thread(func, *args, **kwargs):
        return stripe_session

    monkeypatch.setattr(
        "app.services.stripe.checkout.to_thread",
        mock_to_thread
    )

    # execute service
    with pytest.raises(HTTPException) as exc_info:

        await create_checkout_session(
            tenant=tenant,
            current_user=user,
            plan_id=plan_id,
            db=db
        )

    # generic local persistence failure -> HTTP 500
    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Unable to create Checkout session."

    # verify the service rollback did NOT remove the
    # previously committed checkout.
    result = await db.exec(
        select(StripeCheckoutSession).where(
            StripeCheckoutSession.checkout_id == existing_checkout_id
        )
    )

    checkout = result.first()

    assert checkout is not None
    assert checkout.stripe_session_id == "cs_existing_123"
    assert checkout.stripe_customer_id == "cus_test_123"
    assert checkout.tenant_id == tenant_id
    assert checkout.plan_id == plan_id

    # the duplicate attempted by the service must not persist
    result = await db.exec(
        select(StripeCheckoutSession).where(
            StripeCheckoutSession.tenant_id == tenant_id
        )
    )

    checkouts = result.all()

    assert len(checkouts) == 1




# ensure previous checkout is expired before new one is created
@pytest.mark.asyncio
async def test_create_checkout_session_expires_previous_checkout_before_creating_new_one(
    db,
    monkeypatch
):
    # role
    role = Role(name="user")

    db.add(role)
    await db.flush()

    # user
    user = User(
        username="tenant_a_user",
        email="tenant-a@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(user)
    await db.flush()

    # Plan
    plan = Plan(
        name="pro",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_pro_test",
        credits=1000
    )

    db.add(plan)
    await db.flush()

    # Tenant
    tenant = Tenant(
        name="Tenant A",
        type="team",
        plan_id=plan.plan_id,
        slug="tenant-a-expiration-order",
        credits_remaining=100
    )

    db.add(tenant)
    await db.flush()

    tenant.stripe_customer_id = "cus_test_123"

    # existing open checkout
    previous_checkout = StripeCheckoutSession(
        tenant_id=tenant.tenant_id,
        plan_id=plan.plan_id,
        stripe_session_id="cs_previous_123",
        stripe_customer_id="cus_test_123",
        status="open",
        payment_status="unpaid"
    )

    db.add(previous_checkout)
    await db.flush()

    # track execution order
    execution_order = []

    # mock helpers
    async def mock_get_active_plan(plan_id, db):
        execution_order.append("get_active_plan")
        return plan

    async def mock_ensure_plan_compatible_with_tenant(
        tenant,
        plan
    ):
        execution_order.append("ensure_plan_compatible")

    async def mock_ensure_no_active_subscription(
        tenant,
        db
    ):
        execution_order.append("ensure_no_active_subscription")

    async def mock_ensure_stripe_customer(
        tenant,
        current_user,
        db
    ):
        execution_order.append("ensure_stripe_customer")
        return "cus_test_123"

    async def mock_expire_open_checkout_sessions(
        tenant,
        db
    ):
        execution_order.append("expire_open_checkout_sessions")

        # Verify the previous checkout exists and is still open.
        result = await db.exec(
            select(StripeCheckoutSession).where(
                StripeCheckoutSession.stripe_session_id == "cs_previous_123"
            )
        )

        checkout = result.first()

        assert checkout is not None
        assert checkout.status == "open"

        # simulate what the real helper does.
        checkout.status = "expired"
        db.add(checkout)

        await db.flush()

    async def mock_to_thread(func, *args, **kwargs):
        execution_order.append("stripe_checkout_create")

        # the moment Stripe Checkout is created,
        # the previous checkout must already be expired.
        result = await db.exec(
            select(StripeCheckoutSession).where(
                StripeCheckoutSession.stripe_session_id == "cs_previous_123"
            )
        )

        checkout = result.first()

        assert checkout is not None
        assert checkout.status == "expired"

        return SimpleNamespace(
            id="cs_new_123",
            url="https://checkout.stripe.com/c/pay/new",
            customer="cus_test_123",
            status="open",
            payment_status="unpaid",
            expires_at=None
        )

    # patch helpers where billing.py looks them up
    monkeypatch.setattr(
        "app.services.stripe.checkout.get_active_plan",
        mock_get_active_plan
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_plan_compatible_with_tenant",
        mock_ensure_plan_compatible_with_tenant
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_no_active_subscription",
        mock_ensure_no_active_subscription
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_stripe_customer",
        mock_ensure_stripe_customer
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        mock_expire_open_checkout_sessions
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.to_thread",
        mock_to_thread
    )

    # execute service
    checkout_url = await create_checkout_session(
        tenant=tenant,
        current_user=user,
        plan_id=plan.plan_id,
        db=db
    )

    # verify returned URL
    assert checkout_url == "https://checkout.stripe.com/c/pay/new"

    # verify ordering
    assert execution_order == [
        "get_active_plan",
        "ensure_plan_compatible",
        "ensure_no_active_subscription",
        "ensure_stripe_customer",
        "expire_open_checkout_sessions",
        "stripe_checkout_create"
    ]

    # verify previous checkout is expired
    result = await db.exec(
        select(StripeCheckoutSession).where(
            StripeCheckoutSession.stripe_session_id == "cs_previous_123"
        )
    )

    previous_checkout = result.first()

    assert previous_checkout is not None
    assert previous_checkout.status == "expired"

    # verify new checkout was persisted
    result = await db.exec(
        select(StripeCheckoutSession).where(
            StripeCheckoutSession.stripe_session_id == "cs_new_123"
        )
    )

    new_checkout = result.first()

    assert new_checkout is not None
    assert new_checkout.tenant_id == tenant.tenant_id
    assert new_checkout.plan_id == plan.plan_id
    assert new_checkout.stripe_customer_id == "cus_test_123"
    assert new_checkout.status == "open"
    assert new_checkout.payment_status == "unpaid"

    
    


@pytest.mark.asyncio
async def test_create_checkout_session_uses_same_stripe_customer_id_everywhere(
    db,
    monkeypatch
):
    # role
    role = Role(name="user")

    db.add(role)
    await db.flush()

    # user
    user = User(
        username="tenant_a_customer_test",
        email="tenant-a-customer@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(user)
    await db.flush()

    # plan
    plan = Plan(
        name="pro",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_pro_customer_test",
        credits=1000
    )

    db.add(plan)
    await db.flush()

    # tenant
    tenant = Tenant(
        name="Tenant Customer Test",
        type="team",
        plan_id=plan.plan_id,
        slug="tenant-customer-propagation",
        credits_remaining=100
    )

    db.add(tenant)
    await db.flush()

    # deliberately make this different from the customer returned
    # by ensure_stripe_customer().
    tenant.stripe_customer_id = "cus_old_123"

    expected_customer_id = "cus_new_456"

    # capture arguments sent to Stripe Checkout
    stripe_arguments = {}

    # mock helpers
    async def mock_get_active_plan(plan_id, db):
        return plan

    async def mock_ensure_plan_compatible_with_tenant(
        tenant,
        plan
    ):
        return None

    async def mock_ensure_no_active_subscription(
        tenant,
        db
    ):
        return None

    async def mock_ensure_stripe_customer(
        tenant,
        current_user,
        db
    ):
        # this is the customer the service MUST use.
        return expected_customer_id

    async def mock_expire_open_checkout_sessions(
        tenant,
        db
    ):
        return None

    async def mock_to_thread(func, *args, **kwargs):
        stripe_arguments.update(kwargs)

        return SimpleNamespace(
            id="cs_customer_propagation",
            url="https://checkout.stripe.com/c/pay/customer-test",
            customer=expected_customer_id,
            status="open",
            payment_status="unpaid",
            expires_at=None
        )

    # patch helpers where checkout.py looks them up
    monkeypatch.setattr(
        "app.services.stripe.checkout.get_active_plan",
        mock_get_active_plan
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_plan_compatible_with_tenant",
        mock_ensure_plan_compatible_with_tenant
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_no_active_subscription",
        mock_ensure_no_active_subscription
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_stripe_customer",
        mock_ensure_stripe_customer
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        mock_expire_open_checkout_sessions
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.to_thread",
        mock_to_thread
    )

    # execute service
    checkout_url = await create_checkout_session(
        tenant=tenant,
        current_user=user,
        plan_id=plan.plan_id,
        db=db
    )

    # verify URL
    assert checkout_url == "https://checkout.stripe.com/c/pay/customer-test"

    # verify Stripe received the customer returned by
    # ensure_stripe_customer().
    assert stripe_arguments["customer"] == expected_customer_id
    
    # verify Stripe did NOT receive the tenant's old customer ID.
    assert stripe_arguments["customer"] != "cus_old_123"

    # verify tenant reference
    assert stripe_arguments["client_reference_id"] == str(tenant.tenant_id)
    

    # verify local checkout persistence
    result = await db.exec(
        select(StripeCheckoutSession).where(
            StripeCheckoutSession.stripe_session_id
            == "cs_customer_propagation"
        )
    )

    checkout = result.first()

    assert checkout is not None

    # the exact same Stripe customer must be persisted.
    assert checkout.stripe_customer_id == expected_customer_id

    # verify tenant and plan association.
    assert checkout.tenant_id == tenant.tenant_id
    assert checkout.plan_id == plan.plan_id

    # verify checkout state.
    assert checkout.status == "open"
    assert checkout.payment_status == "unpaid"





@pytest.mark.asyncio
async def test_create_checkout_session_sends_expected_stripe_parameters(
    db,
    monkeypatch
):
    # role
    role = Role(name="user")

    db.add(role)
    await db.flush()

    # user
    user = User(
        username="stripe_payload_user",
        email="stripe-payload@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(user)
    await db.flush()

    # plan
    plan = Plan(
        name="pro",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_payload_test",
        credits=1000
    )

    db.add(plan)
    await db.flush()

    # tenant
    tenant = Tenant(
        name="Payload Tenant",
        type="team",
        plan_id=plan.plan_id,
        slug="stripe-payload-test",
        credits_remaining=100,
        stripe_customer_id="cus_payload_test"
    )

    db.add(tenant)
    await db.flush()

    # capture Stripe request
    stripe_arguments = {}

    # mock helpers
    async def mock_get_active_plan(plan_id, db):
        return plan

    async def mock_ensure_plan_compatible_with_tenant(
        tenant,
        plan
    ):
        return None

    async def mock_ensure_no_active_subscription(
        tenant,
        db
    ):
        return None

    async def mock_ensure_stripe_customer(
        tenant,
        current_user,
        db
    ):
        return "cus_payload_test"

    async def mock_expire_open_checkout_sessions(
        tenant,
        db
    ):
        return None

    async def mock_to_thread(func, *args, **kwargs):
        # The service passes stripe.checkout.Session.create
        # as the callable to to_thread().
        assert func == stripe.checkout.Session.create

        stripe_arguments.update(kwargs)

        return SimpleNamespace(
            id="cs_payload_test",
            url="https://checkout.stripe.com/c/pay/payload-test",
            customer="cus_payload_test",
            status="open",
            payment_status="unpaid",
            expires_at=None
        )

    # patch helpers
    monkeypatch.setattr(
        "app.services.stripe.checkout.get_active_plan",
        mock_get_active_plan
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_plan_compatible_with_tenant",
        mock_ensure_plan_compatible_with_tenant
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_no_active_subscription",
        mock_ensure_no_active_subscription
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.ensure_stripe_customer",
        mock_ensure_stripe_customer
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.expire_open_checkout_sessions",
        mock_expire_open_checkout_sessions
    )

    monkeypatch.setattr(
        "app.services.stripe.checkout.to_thread",
        mock_to_thread
    )

    # Execute service
    checkout_url = await create_checkout_session(
        tenant=tenant,
        current_user=user,
        plan_id=plan.plan_id,
        db=db
    )

    # verify returned URL
    assert (
        checkout_url == "https://checkout.stripe.com/c/pay/payload-test"
    )

    # verify Stripe customer
    assert (
        stripe_arguments["customer"] == "cus_payload_test"
    )

    # verify checkout mode
    assert stripe_arguments["mode"] == "subscription"

    # verify tenant reference
    assert (
        stripe_arguments["client_reference_id"] == str(tenant.tenant_id)
    )

    # verify line items
    assert stripe_arguments["line_items"] == [
        {
            "price": "price_payload_test",
            "quantity": 1
        }
    ]

    # verify success URL
    assert (
        stripe_arguments["success_url"]
        == (
            "http://localhost:8000/billing/success"
            "?session_id={CHECKOUT_SESSION_ID}"
        )
    )

    # verify cancel URL
    assert (
        stripe_arguments["cancel_url"]
        == "http://localhost:8000/billing/cancel"
    )

    # verify metadata
    assert stripe_arguments["metadata"] == {
        "tenant_id": str(tenant.tenant_id),
        "plan_id": plan.plan_id,
        "tenant_type": tenant.type,
        "billing_interval": plan.billing_interval
    }

    # verify local checkout persistence
    result = await db.exec(
        select(StripeCheckoutSession).where(
            StripeCheckoutSession.stripe_session_id == "cs_payload_test"
        )
    )

    checkout = result.first()

    assert checkout is not None
    assert checkout.tenant_id == tenant.tenant_id
    assert checkout.plan_id == plan.plan_id
    assert checkout.stripe_session_id == "cs_payload_test"
    assert checkout.stripe_customer_id == "cus_payload_test"
    assert checkout.status == "open"
    assert checkout.payment_status == "unpaid"
