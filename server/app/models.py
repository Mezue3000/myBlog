# import dependencies
from sqlmodel import SQLModel, Field, Relationship, func, Index, JSON, Text
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from uuid import UUID
from sqlalchemy.orm import Mapped, declared_attr
import sqlalchemy as sa, future_uuid
from sqlalchemy import ForeignKey
from decimal import Decimal





# create link table(m-m relationship) 
class RolePermission(SQLModel, table=True):
    __tablename__ = "role_permissions"

    role_id: int = Field(foreign_key="roles.role_id", primary_key=True)
    permission_id: int = Field(foreign_key="permissions.permission_id", primary_key=True)





# create role model
class Role(SQLModel, table=True):
    __tablename__ = "roles"

    role_id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True, max_length=50)

    # create relationships
    users: list["User"] = Relationship(back_populates="role")
    permissions: list["Permission"] = Relationship(back_populates="roles", link_model=RolePermission)





# create permission model
class Permission(SQLModel, table=True):
    __tablename__ = "permissions"

    permission_id: Optional[int] = Field(default=None, primary_key=True)
    code: str = Field(index=True, unique=True, max_length=100)
    description: Optional[str] = Field(default=None, max_length=255)
    
    # create relationship
    roles: list[Role] = Relationship(back_populates="permissions", link_model=RolePermission)





# tenant-scoped auto-marker mixin
class TenantScopedMixin:
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False)

    @declared_attr
    def __table_args__(cls) -> tuple:
        return (
            sa.Index(f"ix_{cls.__tablename__}_tenant_id", "tenant_id"),
        )

 




# create user model
class User(SQLModel, table=True):
    __tablename__ = "users"
    
    user_id: Optional[int] = Field(default=None, primary_key=True) 
    username: str = Field(max_length=55, nullable=False, unique=True, index=True)
    email: str = Field(max_length=75, nullable=False, unique=True, index=True)
    biography: str = Field(max_length=350, nullable=True)
    password_hash: str = Field(max_length=255, nullable=False)
    country: str = Field(max_length=25, nullable=False)
    city: str = Field(max_length=25, nullable=False)
    is_active: bool = Field(default=True, sa_column_kwargs={"server_default": sa.true()}, nullable=False)
    is_deleted: bool = Field(default=False, sa_column_kwargs={"server_default": sa.false()}, nullable=False)
    deleted_at: Optional[datetime] = Field(default=None, nullable=True)
    provider: str = Field(default="local", max_length=20, nullable=True)
    provider_id: Optional[str] = Field(default=None, max_length=255)
    created_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    )
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True)
    
    # add foreign keys
    role_id: Optional[int] = Field(foreign_key="roles.role_id", index=True, nullable=False)
    active_tenant_id: Optional[UUID] = Field(
        default=None,
        sa_column=sa.Column(
            sa.ForeignKey(
                "tenants.tenant_id", 
                 name="fk_user_active_tenant", 
                 use_alter=True
            ),
            nullable=True,
            index=True
    )   )
    
    # create relationships
    role: Optional[Role] = Relationship(back_populates="users")
    
    tenant_memberships: list["TenantMembership"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"foreign_keys": "[TenantMembership.user_id]"}
    ) 
    
    owned_tenants: list["Tenant"] = Relationship(
        back_populates="owner",
        sa_relationship_kwargs={"foreign_keys": "[Tenant.owner_id]"}
    )
    
    deleted_tenants: list["Tenant"] = Relationship(
        back_populates="deleted_by_user",
        sa_relationship_kwargs={"foreign_keys": "[Tenant.deleted_by]"}
    )

    active_tenant: Optional["Tenant"] = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[User.active_tenant_id]"}
    )
    
    # actions, this user performed
    performed_actions: list["AuditLog"] = Relationship(
        back_populates="actor",
        sa_relationship_kwargs={"foreign_keys": "[AuditLog.actor_id]"}
    )

    # actions, where this user was the target
    targeted_actions: list["AuditLog"] = Relationship(
        back_populates="target_user",
        sa_relationship_kwargs={"foreign_keys": "[AuditLog.target_user_id]"}
    )
    




# create tenant model
class Tenant(SQLModel, table=True):
    __tablename__ = "tenants"
     
    tenant_id: UUID = Field(default_factory=future_uuid.uuid7, primary_key=True, index=True, nullable=False) 
    name: str = Field(max_length=255, index=True, unique=True)
    type: str = Field(default="personal", max_length=25)
    api_call_limit: Optional[int] = Field(default=1000)
    api_calls_used: Optional[int] = Field(default=0)
    
    # add foreign keys
    owner_id: int = Field(foreign_key="users.user_id", index=True, nullable=False)
    plan_id: int = Field(foreign_key="plans.plan_id", index=True)
    deleted_by: Optional[int] = Field(default=None, foreign_key="users.user_id")
    
    slug: str = Field(max_length=100, unique=True, index=True)
    is_active: bool = Field(default=True, sa_column_kwargs={"server_default": sa.true()}, nullable=False)
    is_deleted: bool = Field(default=False, sa_column_kwargs={"server_default": sa.false()}, nullable=False)
    deleted_at: Optional[datetime] = Field(default=None) 
    
    # stripe
    stripe_customer_id: Optional[str] = Field(default=None, max_length=255, index=True)
    
    # credit system
    credits_remaining: int = Field(default=500, nullable=False)
    credits_reset_at: datetime = Field(
        nullable=False, 
        default=lambda: datetime.now(timezone.utc) + timedelta(days=30)
    )
    
    created_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    )
    
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True)
    
    # branding(tenant-dashboard)
    logo_url: Optional[str] = Field(default=None, max_length=255)
    primary_colour: str = Field(default="#1877F2", max_length=25)

    # create relationships
    owner: Optional["User"] = Relationship(
        back_populates="owned_tenants",
        sa_relationship_kwargs={
            "foreign_keys": "[Tenant.owner_id]"
        }
    )
    deleted_by_user: Optional["User"] = Relationship(
        back_populates="deleted_tenants",
        sa_relationship_kwargs={
            "foreign_keys": "[Tenant.deleted_by]"
        }
    )
    members: list["TenantMembership"] = Relationship(back_populates="tenant") 
    tenant_invitations: list["TenantInvitation"] = Relationship(back_populates="tenant")
    projects: list["ApiProject"] = Relationship(back_populates="tenant")
    plan: "Plan" = Relationship(back_populates="tenants")
    subscriptions: list["Subscription"] = Relationship(back_populates="tenant")
    credit_logs: list["CreditLog"] = Relationship(back_populates="tenant")
    billing_audits: list["BillingAudit"] = Relationship(
        back_populates="tenant",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    checkout_sessions: list["StripeCheckoutSession"] = Relationship(
        back_populates="tenant",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    audit_logs: list["AuditLog"] = Relationship(back_populates="tenant")



    
    
# create tenant-membership model
class TenantMembership(SQLModel, TenantScopedMixin, table=True): 
    __tablename__ = "tenant_memberships"

    membership_id: Optional[int] = Field(default=None, primary_key=True)
     
    # add foreign keys
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", nullable=False, index=True)
    user_id: int = Field(foreign_key="users.user_id", nullable=False, index=True)

    role: str = Field(default="member", max_length=10)
    is_active: bool = Field(default=True)
    is_deleted: bool = Field(default=False, sa_column_kwargs={"server_default": sa.false()}, nullable=False)
    deleted_at: Optional[datetime] = Field(default=None)
    deleted_by: Optional[int] = Field(default=None, foreign_key="users.user_id")
    joined_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    )
    
    # create relationships  
    tenant: "Tenant" = Relationship(back_populates="members")
    user: "User" = Relationship(
        back_populates="tenant_memberships",
        sa_relationship_kwargs={"foreign_keys": "[TenantMembership.user_id]"}
    )
    deleted_by_user: Optional["User"] = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[TenantMembership.deleted_by]"}
    )    
    
    # add unique constraint(one user per tenant)
    __table_args__ = (
        sa.Index("ix_tenant_memberships_tenant_id", "tenant_id"),
        sa.UniqueConstraint("tenant_id", "user_id", name="uq_tenant_user")
    )





# create invitation model
class TenantInvitation(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "tenant_invitations"

    invite_id: Optional[int] = Field(default=None, primary_key=True)
    
    # add foreign key
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False)
    
    email: str = Field(max_length=255, default=None, index=True)
    role: str = Field(default="member", max_length=10)
    token: str = Field(max_length=255, nullable=False, unique=True, index=True)
    invited_by: int = Field(foreign_key="users.user_id")
    is_accepted: bool = Field(default=False)
    accepted_at: datetime = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=48))

    # create relationships
    tenant: "Tenant" = Relationship(back_populates="tenant_invitations")
    inviter: Optional["User"] = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[TenantInvitation.invited_by]"}
    )





# create api-project model
class ApiProject(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "api_projects"

    project_id: Optional[int] = Field(default=None, primary_key=True)
    
    # add foreign key
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", nullable=False, index=True, unique=True)
    
    name: str = Field(max_length=100, nullable=False, unique=True)
    description: Optional[str] = Field(default=None, max_length=500)
    environment: str = Field(default="live", max_length=20)

    is_active: bool = Field(default=True)
    created_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    )
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True)

    # create relationships
    tenant: Tenant = Relationship(back_populates="projects")
    api_keys: list["APIKey"] = Relationship(back_populates="project")
    usage_logs: list["APIUsageLog"] = Relationship(back_populates="project")
 




# create api-key model
class APIKey(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "api_keys"

    api_key_id: UUID = Field(default_factory=future_uuid.uuid7, primary_key=True, index=True, nullable=False) 
    
    # add foreign key
    project_id: int = Field(foreign_key="api_projects.project_id", nullable=False, index=True)
    
    key_hash: str = Field(max_length=255, nullable=False, unique=True, index=True)
    key_prefix: str = Field(max_length=30, nullable=False)
    name: str = Field(max_length=100, nullable=False)
    is_revoked: bool = Field(default=False)
    revoked_by: Optional[int] = Field(default=None, foreign_key="users.user_id")
    created_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    )

    expires_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=30))
    last_used_at: Optional[datetime] = Field(default=None)

    # create Relationships
    project: ApiProject = Relationship(back_populates="api_keys")
    revoked_by_user: Optional["User"] = Relationship(
        sa_relationship_kwargs={"foreign_keys": "[APIKey.revoked_by]"}
    )    
    usage_logs: list["APIUsageLog"] = Relationship(back_populates="api_key")
     





# create api-usage-log model
class APIUsageLog(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "api_usage_logs"

    log_id: Optional[int] = Field(default=None, primary_key=True)
    
    # add foreign keys
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False)
    api_key_id: Optional[UUID] = Field(default=None, foreign_key="api_keys.api_key_id", index=True)
    project_id: int = Field(foreign_key="api_projects.project_id", index=True, nullable=False)

    endpoint: Optional[str] = Field(max_length=255)
    method: str = Field(max_length=10)
    status_code: Optional[int] 
    response_time_ms: int = Field(default=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc)) 
    
    # create relationships
    project: ApiProject = Relationship(back_populates="usage_logs")
    api_key: APIKey = Relationship(back_populates="usage_logs")
    
    
    
    
#  create plan model
class Plan(SQLModel, table=True):
    __tablename__ = "plans"
    
    plan_id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=25, nullable=False, index=True)
    billing_interval: str = Field(max_length=15, index=True)
    tenant_type: str = Field(max_length=25, nullable=False, index=True)
    amount: Decimal = Field(default=Decimal("0.00"))
    credits: int = Field(default=0)
    currency: str = Field(max_length=9, default="usd")
    features: Dict[str, Any] = Field(default_factory=dict, sa_type=JSON)
    stripe_price_id: str = Field(max_length=255, nullable=False, unique=True)
    description: Optional[str] = Field(max_length=255)
    is_active: bool = Field(default=True)
    
    # create relationships
    subscriptions: list["Subscription"] = Relationship(back_populates="plan") 
    tenants: list["Tenant"] = Relationship(back_populates="plan")
    
    
    
    
# create subscription model 
class Subscription(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "subscriptions"

    subscription_id: Optional[int] = Field(default=None, primary_key=True)
    
    # add foreign keys
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False, unique=True)
    plan_id: int = Field(foreign_key="plans.plan_id", index=True)
    
    # stripe
    stripe_customer_id: str = Field(max_length=255, nullable=False, index=True)
    stripe_subscription_id: str = Field(max_length=255, unique=True, nullable=False, index=True)
    
    status: str = Field(default="active", max_length=20)
    current_period_start: Optional[datetime] = Field(default=None)
    current_period_end: Optional[datetime] = Field(default=None)
    cancel_at_period_end: bool = Field(default=False)
    cancelled_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc)) 
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True) 

    # create relationships
    plan: Optional[Plan] = Relationship(back_populates="subscriptions")   
    tenant: Optional[Tenant] = Relationship(back_populates="subscriptions")   

    
    
    

# create stripe idempotency model
class WebhookEvent(SQLModel, table=True):
    __tablename__ = "webhook_events"
    
    stripe_event_id: str = Field(max_length=255, primary_key=True, unique=True)
    event_type: str = Field(max_length=100, nullable=False, index=True)
    payload: str = Field(
        sa_column=sa.Column(Text, nullable=False)
    )
    processed: bool = Field(default=False, nullable=False, index=True)
    processed_at: Optional[datetime] = Field(default=None, nullable=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc)) 

    
    
    

# create billing audit-log model
class BillingAudit(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "billing_audits"

    billing_id: Optional[int] = Field(default=None, primary_key=True)
    
    # add foreign key
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False)
    
    event_type: str = Field(max_length=100, index=True)
    stripe_event_id: str = Field(max_length=255, index=True, unique=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # create relationship
    tenant: "Tenant" = Relationship(back_populates="billing_audits")





# create stripe checkout tracking model
class StripeCheckoutSession(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "stripe_checkout_sessions"

    checkout_id: Optional[int] = Field(default=None, primary_key=True)
    stripe_session_id: str = Field(unique=True, index=True)
    stripe_customer_id: str = Field(max_length=255, nullable=False, index=True)
    
    # add foreign keys
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True)
    plan_id: int = Field(foreign_key="plans.plan_id", index=True)
    
    # ex., "open", "complete", "expired"
    status: str = Field(max_length=25, index=True)
    payment_status: str = Field(max_length=75)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = Field(default=None, nullable=True)
    expired_at: Optional[datetime] = Field(default=None, nullable=True)
    
    # create relationship
    tenant: "Tenant" = Relationship(back_populates="checkout_sessions")





# create credits usage log model
class CreditLog(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "credit_logs"

    credit_log_id: Optional[int] = Field(default=None, primary_key=True)
    
    # add foreign key
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", nullable=False, index=True)

    credits_used: int = Field(nullable=False)
    credits_balance_after: int = Field(nullable=False)
    action: str = Field(max_length=30, index=True,)
    description: Optional[str] = Field(default=None, max_length=255,)
    reference_id: Optional[str] = Field(default=None, max_length=255, index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # create relationship
    tenant: Optional["Tenant"] = Relationship(back_populates="credit_logs")





# create audit-log model
class AuditLog(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "audit_logs"

    audit_id: Optional[int] = Field(default=None, primary_key=True)
    
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False)
    
    # who performed the action
    actor_id: int = Field(foreign_key="users.user_id", index=True)

    # who was affected(nullable for system events)
    target_user_id: Optional[int] = Field(default=None, foreign_key="users.user_id", index=True)

    action: str = Field(index=True, max_length=50)

    changes: Optional[Dict[str, Any]] = Field(default=None, sa_type=JSON, sa_column_kwargs={"nullable": True})
    
    # device + request context
    ip_address: Optional[str] = Field(default=None, max_length=70)
    user_agent: Optional[str] = Field(default=None, max_length=180)
   
    # request metadata
    endpoint: Optional[str] = Field(default=None, max_length=70)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), nullable=False)

    # create relationships
    tenant: "Tenant" = Relationship(back_populates="audit_logs")
    actor: Optional["User"] = Relationship(
        back_populates="performed_actions",
        sa_relationship_kwargs={"foreign_keys": "[AuditLog.actor_id]"}
    )

    target_user: Optional["User"] = Relationship(
        back_populates="targeted_actions",
        sa_relationship_kwargs={"foreign_keys": "[AuditLog.target_user_id]"} 
    )





# fix forward reference
RolePermission.model_rebuild()
Role.model_rebuild()
Permission.model_rebuild()
User.model_rebuild()
Tenant.model_rebuild()
TenantMembership.model_rebuild()
TenantInvitation.model_rebuild()
ApiProject.model_rebuild()
APIKey.model_rebuild()
APIUsageLog.model_rebuild()
Plan.model_rebuild()
Subscription.model_rebuild()
WebhookEvent.model_rebuild()
BillingAudit.model_rebuild()
StripeCheckoutSession.model_rebuild()
CreditLog.model_rebuild()
AuditLog.model_rebuild()
