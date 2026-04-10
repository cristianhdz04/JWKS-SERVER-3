import jwt
import time
from fastapi.testclient import TestClient
from app.main import app
from app.keys import get_good_key, get_old_key

# create test client
client = TestClient(app)


# test normal login
def test_login_works():

    # send post request
    res = client.post("/auth")

    # check status is ok
    assert res.status_code == 200

    # get token from response
    token = res.json()["token"]

    # get valid key
    key = get_good_key()

    # decode the token
    decoded = jwt.decode(token, key.public, algorithms=["RS256"])

    # check user id
    assert decoded["sub"] == "user123"


# test expired login
def test_expired_login():

    # request expired token
    res = client.post("/auth?expired=true")

    token = res.json()["token"]

    # get expired key
    key = get_old_key()

    # decode without checking expiration
    decoded = jwt.decode(
        token, key.public, algorithms=["RS256"], options={"verify_exp": False}
    )

    # check expiration is in past
    assert decoded["exp"] < int(time.time())


# test wrong http method
def test_wrong_method():

    res = client.get("/auth")

    # should return method not allowed
    assert res.status_code == 405
