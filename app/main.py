import time
import jwt
from fastapi import FastAPI, Request, HTTPException
from app.keys import get_good_key, get_old_key, get_good_public_keys
from app.utils import make_jwk

# create fastapi app
app = FastAPI()


# @app.get tells fastapi this function runs
# when someone sends a get request to this url
# this endpoint returns the public keys in jwks format
@app.get("/.well-known/jwks.json")
def get_jwks():
    # get valid keys
    keys = get_good_public_keys()
    result = []

    # convert keys to jwk format
    for k in keys:
        result.append(make_jwk(k))

    # return jwks
    return {"keys": result}


# @app.post tells fastapi this function runs
# when someone sends a post request to /auth
# this endpoint creates and returns a jwt
@app.post("/auth")
def login(request: Request):

    # check if expired was requested
    expired = request.query_params.get("expired")

    # use expired key if parameter exists
    if expired:
        key = get_old_key()
        exp_time = key.exp

    # otherwise use valid key
    else:
        key = get_good_key()
        exp_time = key.exp

    # jwt payload
    data = {
        "sub": "user123",  # fake user
        "iat": int(time.time()),  # issued time
        "exp": exp_time,  # expiration time
    }

    # create jwt token
    token = jwt.encode(
        data, key.private, algorithm="RS256", headers={"kid": key.id}  # include key id
    )

    # return token
    return {"token": token}


# @app.get here means this runs if someone uses get on /auth
# we use this to return error because only post is allowed
@app.get("/auth")
def wrong():

    raise HTTPException(status_code=405, detail="Not allowed")
