# import dependencies
from fastapi import Request
from app.rate_limit.policy import RATE_LIMITS





# function to resolve tenant plan/type
def get_limit(request: Request):

    return RATE_LIMITS[
        request.state.tenant_type
    ][
        request.state.tenant_plan
    ]
