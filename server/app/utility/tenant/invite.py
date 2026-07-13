# import dependencies
from app.cores.logging import get_logger
import os, httpx, asyncio
from pydantic import EmailStr





# initialize logger
logger = get_logger(__name__)





MAIL_API_KEY = os.getenv("MAIL_API_KEY")
MAIL_FROM = os.getenv("MAIL_FROM")

if not MAIL_API_KEY or not MAIL_FROM:
    raise RuntimeError("Missing MAIL_API_KEY or MAIL_FROM")

RESEND_API_URL = "https://api.resend.com/emails"





# function to build html
def build_invitation_email_html(
    email: EmailStr,
    tenant_name: str,
    invited_by: str,
    invite_link: str,
    signup_link: str,
) -> str:
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta charset="UTF-8"/>
</head>

<body style="margin:0;padding:0;background:#f6f7fb;font-family:Arial,sans-serif;">

  <table
    role="presentation"
    width="100%"
    cellspacing="0"
    cellpadding="0"
    style="padding:24px 12px;"
  >
    <tr>
      <td align="center">

        <table
          role="presentation"
          width="100%"
          style="
            max-width:600px;
            background:#ffffff;
            border-radius:16px;
            overflow:hidden;
          "
        >

          <!-- Header -->
          <tr>
            <td
              style="
                padding:32px 24px;
                text-align:center;
                background:#111827;
                color:#ffffff;
              "
            >
              <h2
                style="
                  margin:0;
                  font-size:22px;
                  font-weight:700;
                "
              >
                BlogMap
              </h2>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:32px 24px;">

              <p
                style="
                  margin:0 0 16px;
                  color:#374151;
                  font-size:15px;
                "
              >
                Hello <strong>{email}</strong>,
              </p>

              <h1
                style="
                  margin:0 0 16px;
                  font-size:28px;
                  line-height:1.3;
                  color:#111827;
                "
              >
                You've been invited to join
                <br>
                <strong>{tenant_name}</strong>
              </h1>

              <p
                style="
                  margin:0 0 24px;
                  font-size:15px;
                  line-height:1.7;
                  color:#4b5563;
                "
              >
                <strong>{invited_by}</strong>
                has invited you to collaborate in the
                <strong>{tenant_name}</strong> workspace.
              </p>

              <p
                style="
                  margin:0 0 24px;
                  font-size:15px;
                  font-weight:600;
                  color:#111827;
                "
              >
                Choose the option that applies to you:
              </p>

              <!-- Existing User Card -->
              <table
                role="presentation"
                width="100%"
                style="
                  background:#f8fafc;
                  border:1px solid #e5e7eb;
                  border-radius:12px;
                  margin-bottom:16px;
                "
              >
                <tr>
                  <td style="padding:20px;">

                    <div
                      style="
                        font-size:18px;
                        font-weight:700;
                        color:#111827;
                        margin-bottom:8px;
                      "
                    >
                      1. I already have an account
                    </div>

                    <div
                      style="
                        font-size:14px;
                        color:#6b7280;
                        margin-bottom:18px;
                        line-height:1.6;
                      "
                    >
                      Log in with your existing account
                      and accept this invitation.
                    </div>

                    <a
                      href="{invite_link}"
                      style="
                        background:#2563eb;
                        color:#ffffff;
                        text-decoration:none;
                        padding:14px 24px;
                        border-radius:8px;
                        display:inline-block;
                        font-weight:600;
                      "
                    >
                      Log In & Accept Invitation
                    </a>

                  </td>
                </tr>
              </table>

              <!-- New User Card -->
              <table
                role="presentation"
                width="100%"
                style="
                  background:#f8fafc;
                  border:1px solid #e5e7eb;
                  border-radius:12px;
                "
              >
                <tr>
                  <td style="padding:20px;">

                    <div
                      style="
                        font-size:18px;
                        font-weight:700;
                        color:#111827;
                        margin-bottom:8px;
                      "
                    >
                      2. I'm new here
                    </div>

                    <div
                      style="
                        font-size:14px;
                        color:#6b7280;
                        margin-bottom:18px;
                        line-height:1.6;
                      "
                    >
                      Create a new account using
                      <strong>{email}</strong>.
                    </div>

                    <a
                      href="{signup_link}"
                      style="
                        background:#ffffff;
                        color:#111827;
                        text-decoration:none;
                        padding:14px 24px;
                        border-radius:8px;
                        border:1px solid #d1d5db;
                        display:inline-block;
                        font-weight:600;
                      "
                    >
                      Create Account
                    </a>

                  </td>
                </tr>
              </table>

              <!-- Notice -->
              <div
                style="
                  margin-top:24px;
                  padding:16px;
                  background:#f9fafb;
                  border-radius:10px;
                "
              >
                <p
                  style="
                    margin:0 0 10px;
                    font-size:13px;
                    line-height:1.6;
                    color:#4b5563;
                  "
                >
                  <strong>Important:</strong>
                  This invitation is linked to
                  <strong>{email}</strong>.
                </p>

                <p
                  style="
                    margin:0;
                    font-size:13px;
                    line-height:1.6;
                    color:#6b7280;
                  "
                >
                  <strong>Important:</strong> This email will be permanently linked to your account.<br><br>
  
                  Please sign up or sign in using <strong>this exact email address</strong> to avoid duplicate accounts 
                  and ensure proper access to the workspace..
                </p>
              </div>

              <p
                style="
                  margin-top:20px;
                  font-size:13px;
                  color:#9ca3af;
                "
              >
                This invitation expires in 2 days.
              </p>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td
              style="
                padding:20px;
                text-align:center;
                font-size:12px;
                color:#9ca3af;
                background:#f9fafb;
              "
            >
              © {tenant_name} · Powered by BlogMap
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>

</body>
</html>
"""







# function to send tenant iv
async def send_tenant_invitation_email(
    email: EmailStr,
    tenant_name: str,
    invited_by: str,
    invite_token: str,
):
    try:
        invite_link = (
            f"http://localhost:3000/accept_invitation?token={invite_token}"
        )

        signup_link = (
            f"http://localhost:3000/register_invited_user?invite_token={invite_token}"
        )

        subject = f"You are invited to join {tenant_name}"

        html_content = build_invitation_email_html(
            email=email,
            tenant_name=tenant_name,
            invited_by=invited_by,
            invite_link=invite_link,
            signup_link=signup_link,
        )

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

        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                RESEND_API_URL,
                json=payload,
                headers=headers,
            )

        response.raise_for_status()

        logger.info(
            "Invitation email sent successfully",
            extra={"email": email, "tenant": tenant_name},
        )

    except httpx.HTTPStatusError as e:
        logger.error(
            "Resend API error",
            extra={
                "email": email,
                "status": e.response.status_code,
                "body": e.response.text,
            },
            exc_info=True,
        )

    except Exception:
        logger.exception(
            "Unexpected error sending invitation email",
            extra={"email": email},
        )






# function to limit concurrency
async def send_email_with_limit(
    semaphore: asyncio.Semaphore,
    item: dict,
    tenant_name: str,
    invited_by: str,
):
    async with semaphore:
        await send_tenant_invitation_email(
            email=item["email"],
            tenant_name=tenant_name,
            invited_by=invited_by,
            invite_token=item["token"]
        )





# function to send bulk iv
async def send_bulk_invitation_emails(
    invitations: list[dict],
    tenant_name: str,
    invited_by: str,
):
    semaphore = asyncio.Semaphore(10)

    tasks = [
        send_email_with_limit(
            semaphore,
            item,
            tenant_name,
            invited_by
        )
        for item in invitations
    ]

    await asyncio.gather(*tasks)
