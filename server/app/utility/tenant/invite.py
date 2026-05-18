# import dependencies
from app.cores.logging import get_logger
import os, httpx, asyncio
from pydantic import EmailStr





# initialize logging
logger = get_logger(__name__)



# fetch email credentials
MAIL_API_KEY = os.getenv("MAIL_API_KEY")
MAIL_FROM = os.getenv("MAIL_FROM")

if not MAIL_API_KEY or not MAIL_FROM:
    raise RuntimeError(
        "Missing MAIL_API_KEY or MAIL_FROM"
    )

RESEND_API_URL = "https://api.resend.com/emails" 




# function to send token invitation email 
async def send_tenant_invitation_email(
    email: EmailStr,
    tenant_name: str,
    invited_by: str,
    invite_token: str,
):
    try:
        invite_link = (
            f"http://localhost:3000/"
            f"accept-invitation?"
            f"token={invite_token}"
        )

        subject = (
            f"You've been invited "
            f"to join {tenant_name} workspace"
        )

        html_content = f"""
<div style="
    font-family:Arial,sans-serif;
    max-width:520px;
    margin:20px auto;
    padding:24px;
    background:var(--bg,#fff);
    color:var(--text,#111);
    border:1px solid var(--border,#ddd);
    border-radius:12px;
">

  <style>
    :root{{
      --bg:#fff;
      --text:#111;
      --border:#e0e0e0;
      --button:#1877F2;
    }}

    @media (prefers-color-scheme:dark){{
      :root{{
        --bg:#111;
        --text:#eee;
        --border:#444;
        --button:#3B82F6;
      }}
    }}
  </style>

  <h1 style="
      margin:0 0 20px;
      text-align:center;
      color:var(--text);
  ">
      BlogMap
  </h1>

  <p style="margin:0 0 12px;">
      Hello {email},
  </p>

  <p style="margin:0 0 20px;line-height:1.6;">
      <strong>{invited_by}</strong>
      invited you to join the workspace
      <strong>{tenant_name}</strong>.
  </p>

  <p style="margin:0 0 24px;line-height:1.6;">
      Click the button below to accept
      this invitation.
  </p>

  <div style="text-align:center;margin:32px 0;">

    <a
      href="{invite_link}"
      style="
        background:var(--button);
        color:white;
        text-decoration:none;
        padding:14px 24px;
        border-radius:8px;
        display:inline-block;
        font-weight:bold;
      "
    >
      Accept Invitation
    </a>

  </div>

  <p style="
      margin:0 0 16px;
      font-size:14px;
      color:#666;
  ">
      This invitation link expires after 2 days.
  </p>

  <p style="
      margin:0 0 20px;
      line-height:1.6;
  ">
      If you were not expecting this
      invitation, you can safely ignore
      this email.
  </p>

  <div style="
      border-top:1px solid #ddd;
      margin:24px 0;
  "></div>

  <p style="
      margin:0;
      font-size:13px;
      color:#777;
      text-align:center;
  ">
      Best regards,<br/>
      BlogMap Team
  </p>

</div>
"""

        payload = {
            "from": MAIL_FROM,
            "to": [email],
            "subject": subject,
            "html": html_content,
        }

        headers = {
            "Authorization": f"Bearer {MAIL_API_KEY}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(
            timeout=10
        ) as client:

            response = await client.post(
                RESEND_API_URL,
                json=payload,
                headers=headers,
            )

        response.raise_for_status()

        logger.info(
            f"Tenant invitation email "
            f"sent successfully to {email}"
        )

    except httpx.HTTPStatusError as e:
        logger.error(
            f"Resend API error sending "
            f"invitation email to {email}: "
            f"{e.response.status_code} - "
            f"{e.response.text}",
            exc_info=True,
        )

    except httpx.TimeoutException:
        logger.error(
            f"Timeout sending invitation "
            f"email to {email}",
            exc_info=True,
        )

    except httpx.RequestError as e:
        logger.error(
            f"Network error sending "
            f"invitation email to {email}: "
            f"{str(e)}",
            exc_info=True,
        )

    except Exception:
        logger.exception(
            f"Unexpected error sending "
            f"invitation email to {email}"
        )
        
        
        
        
        
# function to limit concurrency
async def send_email_with_limit(
    semaphore: asyncio.Semaphore,
    item: dict,
    tenant_name: str,
    invited_by: str,
):
    async with semaphore:

        try:
            await send_tenant_invitation_email(
                email=item["email"],
                tenant_name=tenant_name,
                invited_by=invited_by,
                invite_token=item["token"],
            )

        except Exception as e:
            logger.error(
                f"Failed to send invitation "
                f"to {item['email']}: {str(e)}"
            )





# function to send bulk invitation
async def send_bulk_invitation_emails(
    invitations: list[dict],
    tenant_name: str,
    invited_by: str,
):
    semaphore = asyncio.Semaphore(10)

    tasks = [
        send_email_with_limit(
            semaphore=semaphore,
            item=item,
            tenant_name=tenant_name,
            invited_by=invited_by,
        )
        for item in invitations
    ]

    await asyncio.gather(*tasks)