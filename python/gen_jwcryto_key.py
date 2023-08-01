from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode, json_decode
import json

# public_key = jwk.JWK()
# # private_key = jwk.JWK()
# private_key = jwk.JWK.generate(kty='RSA', size=2048)
# public_key.import_key(**json_decode(private_key.export_public())) 

# # Write public key to a file
# with open('./public_key.pem', 'wb') as public_file:
#     public_file.write(public_key.export_to_pem(private_key=False))

# # Write private key to a file
# with open('./private_key.pem', 'wb') as private_file:
#     private_file.write(private_key.export_to_pem(private_key=True, password=None))

with open("./public_key.pem", 'rb') as public_file:
    public_key_data = public_file.read()
    
with open("./private_key.pem", 'rb') as private_file:
    private_key_data = private_file.read()

_public_key = jwk.JWK()
_private_key = jwk.JWK()
_public_key.import_from_pem(public_key_data, password=None)
_private_key.import_from_pem(private_key_data, password=None)
    

protected_header = {
    "alg": "RSA-OAEP-256",
    "enc": "A256CBC-HS512",
    "typ": "JWE",
    "kid": _public_key.thumbprint(),
}

payload = {
"pid":"1234567890123",
"phone_number":"0952969820"
}

##### Asymmetric keys #####

# flat enc
# jwetoken = jwe.JWE(json.dumps(payload).encode('utf-8'), recipient=_public_key, protected=protected_header)
# jwetoken = jwe.JWE(json.dumps(payload), recipient=_public_key, protected=protected_header)
# jwetoken = jwe.JWE(str(payload).encode('utf-8'), recipient=_public_key, protected=protected_header)
# enc = jwetoken.serialize()
# print(enc)

# flat dec
# jwetoken = jwe.JWE()
# jwetoken.deserialize(enc, key=_private_key)
# result = jwetoken.payload.decode("utf-8")
# print(result)

# flat dec from FE
enc = {
"ciphertext": "0or7PMQqT59PmGPvhAxr60hD6jjAbZKpeLf3jfjgVLDKY7B_bm7jDn0dfvkPFsQiiJ6pQBOMWZinT3QGvSpECg",
"encrypted_key": "WxeAd9jDTzvHAHErsxgrKyNFtNiE6LKVPbyMo9oFljBLmllXhdy2RyAXJFoc5tm_BTnCMvudFEc4_4fnmRCrBlu5nlp-mMHxUHpLOzOjlGcHelvqcvWhrM0co2tx8MNUjfZZbyWJJkBzwfcIWv1m3s-yaquLbjktOIA2x0cJe55-vKEr1vQv5GFRnVIglHdhxe38-iV2cFzHBjBfXjGRn21naxEw6s-8ldGw6nmtq0C2z9VqBeetIhYXR5A9VK4t7_fh_zIMHclC0yWP_XgdfOmnhwNexIvCAxK3B6r_qiozlRyqKHnfo6K0xQKKIUjQc9uGulyrsgPkoRfOlPtSdw",
"iv": "hJ6A6GjFs7KS6m4qvJe0Pg",
"protected": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidWtxeFZMOVgxWHpkTzZRUUljaHFtNGo5dE8ySnNwc2FrbmYtSWhmMjM3byIsInR5cCI6IkpXRSJ9",
"tag": "peabW6lHxm7vinFk4CRxHCFeJV8T_584dqAjmVuRo6w"
}
jwetoken = jwe.JWE()
jwetoken.deserialize(json.dumps(enc), key=_private_key)
result = jwetoken.payload.decode("utf-8")
# print(json.loads(result))
print(result)

##### Symmetric keys #####
# enc = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.gUh9FHR2ZNLkXp6itKjn4KsQqcooTpqMVfyp2mRDhHZd7W6fXzhghnr8VUR5rBAz2mei5elxFwC5R_vQYMRxNPs8lyXwEYz7k2Hv9OmX1K-_p4q7FIODCD_C59WyzKat4-W83iZ5S1BLFrSpyym2CkeaT08vEVgRhmBxkFexL3AUUNnmozkUcgQv4_TGBy7poiuMS-BaP3Of5rszw6Gi9jkUBM_r9wSq9VCiU6Qmk3PThTLX45TO-zJhApGhNl4J7BiB73-6-PSxlVHaRQXFDgLPBWKqmLzIvN52CdeCXjBUoFVYPP92Pgw7j8gRRC6GU49poLuDSIexkdKxtsqGSg.EdDrz-FR2DZOdmwWb3XuMA.vscOcLN2nm04MK70-O7Ztg.rNpKVt7RwMQiGWlWfYe4FO3fs5K8XJgE7-0s5nVNkYA'
# jwetoken = jwe.JWE()
# jwetoken.deserialize(enc)
# jwetoken.decrypt(_private_key)
# payload = jwetoken.payload