# rate limit policy
RATE_LIMITS = {
    
    "personal": {
        "free": "100/minute",
        "pro": "1000/minute",
        "enterprise": "10000/minute",
    },


    "team": {
        "pro": "10000/minute",
        "enterprise": "100000/minute",
    },


    "headless_api": {
        "free": "10000/minute",
        "pro": "100000/minute",
        "enterprise": "1000000/minute",
    },

}



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
}
