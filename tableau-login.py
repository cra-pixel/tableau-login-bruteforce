import os
import sys
import requests
import json

import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode

tab_server_url = "http://server"
# Make sure to change your username
tableau_username = "user@domain.com"
your_password = b"secretpassword"
print( tableau_username )

def _encode_for_display(text):
     return text.encode('ascii', errors="backslashreplace").decode('utf-8')

# Establish a session so we can retain the cookies
session = requests.Session()

def generatePublicKey(): 
      payload = "{\"method\":\"generatePublicKey\",\"params\":{}}"
      endpoint = "generatePublicKey"
      url = tab_server_url + "/vizportal/api/web/v1/"+endpoint
      headers = {
      'content-type': "application/json;charset=UTF-8",
      'accept': "application/json, text/plain, */*",
      'cache-control': "no-cache"
      }
      response = session.post(url, data=payload, headers=headers)
      response_text = json.loads(_encode_for_display(response.text))
      response_values = {"keyId":response_text["result"]["keyId"], "n":response_text["result"]["key"]["n"],"e":response_text["result"]["key"]["e"]}
      return response_values
      
# Encrypt with RSA public key (it's important to use PKCS11)
def assymmetric_encrypt(val, public_key):
     modulusDecoded = int(public_key["n"], 16)
     exponentDecoded = int(public_key["e"], 16)
     keyPub = RSA.construct((modulusDecoded, exponentDecoded))
     # Generate a cypher using the PKCS1.5 standard
     cipher = PKCS1_v1_5.new(keyPub)
     return cipher.encrypt(val)

def vizportalLogin(encryptedPassword, keyId):
     encodedPassword = binascii.b2a_hex(encryptedPassword) 
     payload = "{\"method\":\"login\",\"params\":{\"username\":\"%s\", \"encryptedPassword\":\"%s\", \"keyId\":\"%s\"}}" % (tableau_username, encodedPassword,keyId)
     endpoint = "login"
     url = tab_server_url + "/vizportal/api/web/v1/"+endpoint
     headers = {
     'content-type': "application/json;charset=UTF-8",
     'accept': "application/json, text/plain, */*",
     'cache-control': "no-cache"
     }
     print(payload)
     response = session.post(url, data=payload, headers=headers)
     return response

# Generate a pubilc key that will be used to encrypt the user's password
public_key = generatePublicKey()
pk = public_key["keyId"]
 
# Encrypt the password used to login
encryptedPassword = assymmetric_encrypt(your_password,public_key)

# Capture the response
login_response = vizportalLogin(encryptedPassword, pk)

if login_response.status_code == 200:
    print( "Login to Vizportal Successful!")

print(login_response.headers)

# Parse the cookie
sc = login_response.headers["Set-Cookie"]

set_cookie = dict(item.split("=") for item in sc.split(";"))
xsrf_token = set_cookie[" HttpOnly, XSRF-TOKEN"]
workgroup_session_id = set_cookie["workgroup_session_id"]

