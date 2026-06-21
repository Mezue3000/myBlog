# import dependencies
from sqlmodel import SQLModel, Field, Relationship, func, Index, JSON, Text
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from uuid import UUID
from sqlalchemy.orm import Mapped, declared_attr
import sqlalchemy as sa, future_uuid
from sqlalchemy import ForeignKey





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
        sa_relationship_kwargs={
            "foreign_keys": "[Tenant.owner_id]"
        }
    )
    
    deleted_tenants: list["Tenant"] = Relationship(
        back_populates="deleted_by_user",
        sa_relationship_kwargs={
            "foreign_keys": "[Tenant.deleted_by]"
        }
    )

    active_tenant: Optional["Tenant"] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[User.active_tenant_id]"
        }
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
    
    # add foreign key
    owner_id: int = Field(foreign_key="users.user_id", index=True, nullable=False) 
    
    slug: str = Field(max_length=100, unique=True, index=True)
    is_active: bool = Field(default=True, sa_column_kwargs={"server_default": sa.true()}, nullable=False)
    is_deleted: bool = Field(default=False, sa_column_kwargs={"server_default": sa.false()}, nullable=False)
    deleted_at: Optional[datetime] = Field(default=None) 
    deleted_by: Optional[int] = Field(default=None, foreign_key="users.user_id")
    
    # stripe
    stripe_customer_id: Optional[str] = Field(default=None, max_length=255, index=True)
    
    created_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    )
    
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True)
    
    # subscription
    plan: str = Field(default="free", max_length=25)
    max_members: int = Field(default=1)
    
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
    subscriptions: list["Subscription"] = Relationship(back_populates="tenant")
    audit_logs: list["AuditLog"] = Relationship(back_populates="tenant")
    


    
    
# create tenant-membership model
class TenantMembership(SQLModel, TenantScopedMixin, table=True): 
    __tablename__ = "tenant_memberships"

    membership_id: Optional[int] = Field(default=None, primary_key=True)
     
    # add foreign keys
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", nullable=False, index=True)
    user_id: int = Field(foreign_key="users.user_id", nullable=False, index=True)

    role: str = Field(default="member", max_length=50)
    max_members: int = Field(default=50)
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
        sa_relationship_kwargs={
            "foreign_keys": "[TenantMembership.user_id]"
        }
    )
    deleted_by_user: Optional["User"] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[TenantMembership.deleted_by]"
        }
    )    
    
    # add unique constraint(one user per tenant)
    __table_args__ = (
        sa.Index("ix_tenant_memberships_tenant_id", "tenant_id"),
        sa.UniqueConstraint("tenant_id", "user_id", name="uq_tenant_user"),
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
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=48))

    # create relationships
    tenant: "Tenant" = Relationship(back_populates="tenant_invitations")
    inviter: Optional["User"] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[TenantInvitation.invited_by]"
        }
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
    # live, test, development

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





# calculate timestamp expiration
def get_default_expiration() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=30)



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

    expires_at: Optional[datetime] = Field(default_factory=get_default_expiration, nullable=True)
    last_used_at: Optional[datetime] = Field(default=None)

    # create Relationships
    project: ApiProject = Relationship(back_populates="api_keys")
    revoked_by_user: Optional["User"] = Relationship(
        sa_relationship_kwargs={
            "foreign_keys": "[APIKey.revoked_by]"
        }
    )    
    usage_logs: list["APIUsageLog"] = Relationship(back_populates="api_key")
     





# create api-usage-log model
class APIUsageLog(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "api_usage_logs"

    log_id: Optional[int] = Field(default=None, primary_key=True)
    
    # add foreign keys
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False)
    api_key_id: Optional[UUID] = Field(default=None, foreign_key="api_keys.api_key_id", index=True)

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
    name: str = Field(max_length=25, nullable=False)
    type: str = Field(max_length=25)
    price_monthly: float = Field(default=0.0)
    price_yearly: float = Field(default=0.0)
    currency: str = Field(max_length= 15, default="usd")
    stripe_price_id: str = Field(max_length=255, nullable=False, unique=True)
    is_active: bool = Field(default=True)
    
    # create relationships
    subscriptions: list["Subscription"] = Relationship(back_populates="plan") 
    
    
    
    
    
# create subscription model 
class Subscription(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "subscriptions"

    subscription_id: Optional[int] = Field(default=None, primary_key=True)
    
    # add foreign keys
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False)
    plan_id: int = Field(foreign_key="plans.plan_id", index=True)
    
    # stripe
    stripe_customer_id: str = Field(max_length=255, nullable=False, index=True)
    stripe_subscription_id: str = Field(max_length=255, unique=True, nullable=False, index=True)
    
    status: str = Field(default="active", max_length=20)
    type: str = Field(max_length=25)
    current_period_start: Optional[datetime] = Field(default=None)
    current_period_end: Optional[datetime] = Field(default=None)
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

    
    
    
    
# create audit-log model
class AuditLog(SQLModel, TenantScopedMixin, table=True):
    __tablename__ = "audit_logs"

    audit_id: Optional[int] = Field(default=None, primary_key=True)
    
    tenant_id: UUID = Field(foreign_key="tenants.tenant_id", index=True, nullable=False)
    
    # who performed the action
    actor_id: int = Field(foreign_key="users.user_id", index=True)

    # who was affected (nullable for system events)
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
AuditLog.model_rebuild()