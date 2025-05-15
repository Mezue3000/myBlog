# import dependencies
from sqlmodel import SQLModel, Field, Relationship, func
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Mapped