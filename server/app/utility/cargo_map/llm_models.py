# import dependencies
import os
from app.cores.logging import get_logger
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.fallback import FallbackModel





# initialize logger
logger = get_logger(__name__)




# primary model: quen through grok
primary_qwen = OpenAIChatModel(
    model_name="qwen-2.5-72b-instruct",
    base_url="https://api.groq.com/openai/v1",
    api_key=os.getenv("QWEN_MODEL")
)





# first fallback: gemini
fallback_gemini = GoogleModel(
    model_name="gemini-2.5-flash",
    api_key=os.getenv("GOOGLE_FLASH")
)




# second fallback: deepseek through openrouter
fallback_deepseek = OpenAIChatModel(
    model_name="deepseek/deepseek-v3",
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("DEEPSEEK_MODEL")
)




# reselient fallback chain
resilient_model = FallbackModel(
    primary_qwen,
    fallback_gemini,
    fallback_deepseek
)
