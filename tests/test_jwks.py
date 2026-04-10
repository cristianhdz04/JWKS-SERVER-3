from fastapi.testclient import TestClient
from app.main import app
from app.keys import get_old_key

# create test client
client = TestClient(app)


# test jwks endpoint works
def test_jwks_works():

    # send get request
    res = client.get("/.well-known/jwks.json")

    # check status code
    assert res.status_code == 200


# test expired key is not included
def test_old_key_not_inside():
    # get jwks response
    res = client.get("/.well-known/jwks.json")
    data = res.json()
    # get expired key id
    old = get_old_key().id
    # list to store key ids
    kids = []
    # save all returned key ids
    for k in data["keys"]:
        kids.append(k["kid"])

    # make sure expired key is not there
    assert old not in kids
