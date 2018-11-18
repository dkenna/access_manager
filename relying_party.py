import requests
import json
import sys
from urllib.parse import urlparse, parse_qs

"""
    - define URLs, headers and data
    - log in
    - get authorization code
    - get access token 
    - get userinfo
"""

#   URLs
url_authorize = "http://localhost:8000/openid/authorize"
url_login = "http://localhost:8000/token_login/"
url_token = "http://localhost:8000/openid/token/"
url_userinfo = "http://localhost:8000/openid/userinfo/"

#   headers
h_token = {"Cache-Control": "no-cache", \
            "Content-Type": "application/x-www-form-urlencoded", \
            }
h_userinfo = {"Cache-Control": "no-cache"}
h_userinfo_bearer = {"Cache-Control": "no-cache","Bearer":""}
h_authorize = {"Cache-Control":"no-cache","Content-Type":"application/x-www-form-urlencoded"}
h_login = {"Content-Type": "application/json"}

#   data
d_token = {"client_id":"488892", \
            "client_secret":"f6095c4df003c5ce386bca06a885a44f03ce8ecdc0151167aa742c1c", \
            "code":"%", "redirect_uri":"http://localhost:3000/oidc/callback/", \
            "grant_type":"authorization_code"}
d_authorize = {"client_id":"488892", \
            "scope":"openid email profile", \
            "state":"889822", "redirect_uri":"http://localhost:3000/oidc/callback/", \
            "response_type":"code"}
d_login = {"username":sys.argv[1],"signed_challenge":sys.argv[2]}

#   pass a username and signed_challenge
if len(sys.argv) < 3:
    print("no code given")
    sys.exit(-1)

#    logging in and opening a session
session = requests.Session()
r = session.post(url_login,headers=h_login,json=d_login)
print(r.status_code)
print(r.text)

#    gettin autorization code
r = session.get(url_authorize,headers=h_authorize,params=d_authorize)
"""for resp in r.history:
    print(resp.status_code, resp.url)"""
print(r.status_code)
print(r.text)

#   getting the code from the redirect URL
o = urlparse(r.history[1].url)
query = parse_qs(o.query)
code = query["code"][0]
d_token["code"] = code

#   obtain the token
r = requests.post(url_token, headers=h_token, data=d_token)
print(r.status_code)
print(r.text)
access_token = json.loads(r.text)["access_token"]
print(access_token)

#   get userinfo
r = requests.get(url_userinfo + "?access_token="+access_token, headers=h_userinfo)
print(r.status_code)
print(r.text)
