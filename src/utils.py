import requests
import os
import base64
from urllib.parse import urljoin
who_am_i_endpoint = 'v4/auth/principal'

def domino_authenticate(user_name,password):
    if (password == 'xxx'):
        return get_user_name(user=user_name)
    else:
        raise Exception('User Id or Password not correct')

def read_auth_tokens(request:requests.Request):
    authtoken=request.headers['Authorization']
    bearer_token=''
    user_name=''
    password=''
    if (authtoken.startswith("Bearer ")):
        bearer_token = authtoken[7:]
        print(authtoken)
        print(bearer_token)
        return get_user_name(token=bearer_token)
    if (authtoken.startswith("Basic ")):
        basic_auth = base64.b64decode(authtoken[6:])
        print(basic_auth)
        lst = basic_auth.decode("utf-8").split(":")
        user_name= lst[0]
        password = lst[1]
        ##Authenticate here
        return domino_authenticate(user_name,password)


def get_user_name(token='',user=''):
    if(len(token)>0): #Use Token Based Auth
        url = urljoin(os.environ['DOMINO_API_HOST'],who_am_i_endpoint)
        headers={'X-Domino-Api-Key':token}
        print(url)
        print(headers)
        resp = requests.get(url, headers=headers)
        print(resp)
        return resp.json()['canonicalName']
    else:
        return user
