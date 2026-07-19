# import dependencies
from fastapi import Request
from app.rate_limit.resolver import get_plan_feature





# platform authentication policy
AUTH_LIMITS = {
    "ip":"20/minute",
    "login":"5/minute",
    "register":"3/minute",
    "update_user":"3/10minute",
    "update_email":"3/hour",
    "verify":"3/hour",
    "forgot_password":"3/hour",
    "reset_password":"3/hour",
    "delete_user":"3/hour",
    "ip_admin_read":"30/minute",
    "ip_admins_read":"60/minute",
    "ip_admin_write":"30/minute",
    "admin_patch":"30/minute",
    "admin_delete":"10/minute",
    "admin_restore":"10/minute",
    "admin_deactivate":"10/minute",
    "get_data":"300/minute",
    "accept_iv":"5/minute"
}



# headless api auth policy
API_LIMITS = {
    "create_project":"3/minute",
    "generate_key":"5/minute",
    "list_key":"5/minute",
    "usage_logs":"5/minute",
    "revoke_key":"3/minute"
}



# tenant auth policy
TENANT_LIMITS = {
    "team":"5/10minute",
    "list_tenant":"3/minute",
    "switch_tenant":"5/minute",
    "update_tenant":"2/minute",
    "delete_tenant":"3/hour",
    "admin_iv":"30/minute",
    "admin_delete":"5/minute",
    "admin_patch":"10/minute",
    "create_session":"3/minute"
}





# function to extract tenant-plan limits
def tenant_rate_limit(request: Request) -> str:
    tenant = request.state.tenant

    rpm = get_plan_feature(tenant, "rate_limit_rpm")

    if rpm is None:
        raise RuntimeError(f"Plan '{tenant.plan.name}' is missing 'rate_limit_rpm'.")

    return f"{rpm}/minute"





# @limiter.limit(tenant_rate_limit, key_func=tenant_key_func)
