# import dependencies
from app.models import Tenant
from typing import Any




# function to extract plan-limits
def get_plan_feature(
    tenant: Tenant,
    feature: str,
    default: Any = None
) -> Any:
    if tenant.plan is None:
        return default

    features = tenant.plan.features or {}

    return features.get(feature, default)





# tenant = request.state.tenant

# rpm = get_plan_feature(tenant, "rate_limit_rpm", 30)
# max_members = get_plan_feature(tenant, "max_team_members")
# api_access = get_plan_feature(tenant, "api_access", False)
# max_projects = get_plan_feature(tenant, "max_projects", 1)
