# import dependencies
from fastapi import FastAPI
from app.cruds import users, login


# initialize fastapi
app = FastAPI()


# include all routers
app.include_router(users.router)
app.include_router(login.router)