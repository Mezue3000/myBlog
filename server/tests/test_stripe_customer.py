# import dependencies
import pytest, stripe, os
from decimal import Decimal
from unittest.mock import AsyncMock, patch
from app.models import Tenant, User, Plan, Role
from app.utility.stripe.helpers import ensure_stripe_customer
from sqlmodel import select
from sqlalchemy.exc import IntegrityError





# test to confirm stripe returns existing customer
@pytest.mark.asyncio
async def test_ensure_stripe_customer_returns_existing_customer(db):

    plan = Plan(
        name="Free",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_free",
        description="Test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(
        name="member"
    )

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="Test Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="test-tenant",
        stripe_customer_id="cus_existing_123"
    )

    current_user = User(
        username="testuser",
        email="test@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        result = await ensure_stripe_customer(
            tenant=tenant,
            current_user=current_user,
            db=db
        )

    assert result == "cus_existing_123"

    mock_create.assert_not_called()





# confirm stripe creates new customer
@pytest.mark.asyncio
async def test_ensure_stripe_customer_creates_new_customer(db):

    plan = Plan(
        name="Free",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_free_2",
        description="Test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_new_customer")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="New Stripe Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="new-stripe-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="newstripeuser",
        email="newstripe@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.return_value.id = "cus_test_123"

        result = await ensure_stripe_customer(
            tenant=tenant,
            current_user=current_user,
            db=db
        )

    assert result == "cus_test_123"
    assert tenant.stripe_customer_id == "cus_test_123"

    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args.kwargs

    assert call_kwargs["email"] == current_user.email
    assert call_kwargs["name"] == tenant.name

    assert call_kwargs["metadata"]["tenant_id"] == str(
        tenant.tenant_id
    )

    assert call_kwargs["metadata"]["owner_id"] == str(
        current_user.user_id
    )

    assert call_kwargs["metadata"]["tenant_type"] == tenant.type

    assert call_kwargs["options"]["idempotency_key"] == (
        f"tenant-customer-{tenant.tenant_id}"
    )
    




# ensure stripe propagates rate limit error 
@pytest.mark.asyncio
async def test_ensure_stripe_customer_propagates_rate_limit_error(db):

    plan = Plan(
        name="Free Rate Limit",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_rate_limit",
        description="Rate limit test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(
        name="member_rate_limit"
    )

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="Rate Limit Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="rate-limit-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="ratelimituser",
        email="ratelimit@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.side_effect = stripe.error.RateLimitError(
            message="Too many requests"
        )

        with pytest.raises(stripe.error.RateLimitError):
            await ensure_stripe_customer(
                tenant=tenant,
                current_user=current_user,
                db=db
            )

    mock_create.assert_called_once()

    assert tenant.stripe_customer_id is None
    
    
  
  
    
# confirm authentication error are thrown by stripe    
@pytest.mark.asyncio
async def test_ensure_stripe_customer_propagates_authentication_error(db):

    plan = Plan(
        name="Free Auth Error",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_auth_error",
        description="Authentication error test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_auth_error")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="Authentication Error Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="authentication-error-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="autherroruser",
        email="autherror@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.side_effect = stripe.error.AuthenticationError(message="Invalid API key")

        with pytest.raises(stripe.error.AuthenticationError):
            await ensure_stripe_customer(
                tenant=tenant,
                current_user=current_user,
                db=db
            )

    mock_create.assert_called_once()

    assert tenant.stripe_customer_id is None
    
    
    
    

# ensure stripe propagates connection error
@pytest.mark.asyncio
async def test_ensure_stripe_customer_propagates_api_connection_error(db):

    plan = Plan(
        name="Free API Connection Error",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_api_connection_error",
        description="API connection error test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_api_connection_error")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="API Connection Error Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="api-connection-error-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="apiconnectionuser",
        email="apiconnection@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.side_effect = stripe.error.APIConnectionError(message="Unable to connect to Stripe")

        with pytest.raises(stripe.error.APIConnectionError):
            await ensure_stripe_customer(
                tenant=tenant,
                current_user=current_user,
                db=db
            )

    mock_create.assert_called_once()

    assert tenant.stripe_customer_id is None
    
    

# ensure stripe propagates invalid request error
@pytest.mark.asyncio
async def test_ensure_stripe_customer_propagates_invalid_request_error(db):

    plan = Plan(
        name="Free Invalid Request",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_invalid_request",
        description="Invalid request test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_invalid_request")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="Invalid Request Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="invalid-request-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="invalidrequestuser",
        email="invalidrequest@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.side_effect = stripe.error.InvalidRequestError(
            message="Invalid Stripe request",
            param="email"
        )

        with pytest.raises(stripe.error.InvalidRequestError):
            await ensure_stripe_customer(
                tenant=tenant,
                current_user=current_user,
                db=db
            )

    mock_create.assert_called_once()

    assert tenant.stripe_customer_id is None
    
    
    
    
# ensure stripe propagates stripe error
@pytest.mark.asyncio
async def test_ensure_stripe_customer_propagates_stripe_error(db):

    plan = Plan(
        name="Free Stripe Error",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_stripe_error",
        description="Stripe error test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_stripe_error")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="Stripe Error Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="stripe-error-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="stripeerroruser",
        email="stripeerror@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.side_effect = stripe.error.StripeError(message="Unexpected Stripe error")

        with pytest.raises(stripe.error.StripeError):
            await ensure_stripe_customer(
                tenant=tenant,
                current_user=current_user,
                db=db
            )

    mock_create.assert_called_once()
    
    assert tenant.stripe_customer_id is None
    
    
    


# ensure stripe propagate card error
@pytest.mark.asyncio
async def test_ensure_stripe_customer_propagates_card_error(db):

    plan = Plan(
        name="Free Card Error",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_card_error",
        description="Card error test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_card_error")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="Card Error Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="card-error-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="carderroruser",
        email="carderror@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.side_effect = stripe.error.CardError(
            message="Card was declined",
            param="card",
            code="card_declined"
        )

        with pytest.raises(stripe.error.CardError):
            await ensure_stripe_customer(
                tenant=tenant,
                current_user=current_user,
                db=db
            )

    mock_create.assert_called_once()

    assert tenant.stripe_customer_id is None
    
    
    
    
# ensure stripe throws generic exception
@pytest.mark.asyncio
async def test_ensure_stripe_customer_propagates_generic_exception(db):

    plan = Plan(
        name="Free Generic Error",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_generic_error",
        description="Generic error test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_generic_error")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="Generic Error Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="generic-error-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="genericerroruser",
        email="genericerror@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.side_effect = RuntimeError("Unexpected application error")

        with pytest.raises(RuntimeError, match="Unexpected application error"):
            await ensure_stripe_customer(
                tenant=tenant,
                current_user=current_user,
                db=db
            )

    mock_create.assert_called_once()

    assert tenant.stripe_customer_id is None
    
    
    
    
# ensure stripe customer handles db failure 
@pytest.mark.asyncio
async def test_ensure_stripe_customer_handles_db_flush_failure(db):

    plan = Plan(
        name="Free DB Flush Error",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_db_flush_error",
        description="DB flush error test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_db_flush_error")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="DB Flush Error Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="db-flush-error-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="dbflusherroruser",
        email="dbflusherror@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.return_value.id = "cus_db_flush_error"

        with patch.object(
            db,
            "flush",
            side_effect=RuntimeError("Database flush failed")
        ) as mock_flush:

            with pytest.raises(
                RuntimeError,
                match="Database flush failed"
            ):
                await ensure_stripe_customer(
                    tenant=tenant,
                    current_user=current_user,
                    db=db
                )

    mock_create.assert_called_once()
    mock_flush.assert_called_once()

    assert tenant.stripe_customer_id == "cus_db_flush_error"




# ensure rollback after flush failure
@pytest.mark.asyncio
async def test_ensure_stripe_customer_requires_rollback_after_flush_failure(db):

    plan = Plan(
        name="Free DB Transaction Test",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_db_transaction",
        description="DB transaction test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_db_transaction")

    db.add(role)
    await db.flush()

    tenant = Tenant(
        name="DB Transaction Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="db-transaction-tenant",
        stripe_customer_id=None
    )

    current_user = User(
        username="dbtransactionuser",
        email="dbtransaction@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    await db.flush()

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.return_value.id = "cus_db_transaction"

        with patch.object(
            db,
            "flush",
            side_effect=RuntimeError("Database flush failed")
        ):

            with pytest.raises(
                RuntimeError,
                match="Database flush failed"
            ):
                await ensure_stripe_customer(
                    tenant=tenant,
                    current_user=current_user,
                    db=db
                )

    mock_create.assert_called_once()

    # verify whether the session can still be used.
    result = await db.exec(
        select(Tenant).where(Tenant.tenant_id == tenant.tenant_id)
    )

    loaded_tenant = result.first()

    assert loaded_tenant is not None




# ensure stripe customer flush failure requires rollback
@pytest.mark.asyncio
async def test_ensure_stripe_customer_real_flush_failure_requires_rollback(db):

    plan = Plan(
        name="Free Real Flush Error",
        billing_interval="month",
        tenant_type="personal",
        amount=Decimal("0.00"),
        credits=100,
        currency="usd",
        features={},
        stripe_price_id="price_test_real_flush_error",
        description="Real flush error test plan",
        is_active=True
    )

    db.add(plan)
    await db.flush()

    role = Role(name="member_real_flush_error")

    db.add(role)
    await db.flush()

    # first tenant establishes the unique slug.
    existing_tenant = Tenant(
        name="Existing Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="real-flush-duplicate-slug",
        stripe_customer_id=None
    )

    db.add(existing_tenant)
    await db.flush()

    tenant = Tenant(
        name="Duplicate Tenant",
        type="personal",
        plan_id=plan.plan_id,
        slug="real-flush-duplicate-slug",
        stripe_customer_id=None
    )

    current_user = User(
        username="realflushuser",
        email="realflush@example.com",
        password_hash="hashed-password",
        role_id=role.role_id
    )

    db.add(tenant)
    db.add(current_user)

    with patch(
        "app.utility.stripe.helpers.stripe.Customer.create"
    ) as mock_create:

        mock_create.return_value.id = "cus_real_flush_failure"

        # the duplicate slug causes the REAL database flush
        # inside ensure_stripe_customer() to fail.
        with pytest.raises(IntegrityError):
            await ensure_stripe_customer(
                tenant=tenant,
                current_user=current_user,
                db=db
            )

    mock_create.assert_called_once()

    # stripe succeeded before the database failure.
    assert tenant.stripe_customer_id == "cus_real_flush_failure"

    # test whether another DB operation can execute before rollback.
    with pytest.raises(Exception):
        await db.exec(
            select(Tenant).where(Tenant.tenant_id == existing_tenant.tenant_id)
        )
