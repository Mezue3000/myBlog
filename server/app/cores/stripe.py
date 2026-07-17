# import dependency
from dotenv import load_dotenv
import stripe, os



# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/platform/.env")



stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

if not stripe.api_key:
    raise RuntimeError("STRIPE_SECRET_KEY environment variable is not set.")

stripe.max_network_retries = 2
