
# @router.post("/posts", dependencies=[Depends(verify_csrf)])
# async def create_post(
#     current_user: User = Depends(get_current_user),
# ):
#     return {"detail": "Post created"}
