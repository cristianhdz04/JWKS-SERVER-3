import base64


# convert number to base64 format
def to_base64(num):

    # calculate byte length
    length = (num.bit_length() + 7) // 8

    # convert to base64 string
    return (
        base64.urlsafe_b64encode(num.to_bytes(length, "big"))
        .rstrip(b"=")
        .decode("utf-8")
    )


# convert key to jwk format
def make_jwk(key):

    # get public key numbers
    numbers = key.public.public_numbers()

    # return jwk dictionary
    return {
        "kty": "RSA",  # key type
        "use": "sig",  # used for signature
        "alg": "RS256",  # algorithm
        "kid": key.id,  # key id
        "n": to_base64(numbers.n),  # modulus
        "e": to_base64(numbers.e),  # exponent
    }
