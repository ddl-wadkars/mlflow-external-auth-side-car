import requests
import os
from urllib.parse import urljoin
who_am_i_endpoint = 'v4/auth/principal'

def create_mlflow_token(api_token='',project_name=''):
    if(not project_name==''):
        return api_token + '|' + project_name
    else:
        return api_token

def parse_mlflow_token(mlflow_token):
    result = mlflow_token.split('|')
    domino_attributes = {}
    domino_attributes['token'] = result[0]
    domino_attributes['project'] = ''
    if(len(result)>1):
        domino_attributes['project'] = result[1]
    return domino_attributes

def read_mlflow_token(request:requests.Request):
    print(request.headers)
    if('Authorization' not in request.headers):
        return ''
    else:
        authtoken = request.headers['Authorization']
        mlflow_token = authtoken[7:]
        return mlflow_token

def domino_authenticate(user_name,password):
    if (password == 'xxx'):
        return get_user_name(user=user_name)
    else:
        raise Exception('User Id or Password not correct')

def get_domino_project(domino_attributes):
    return domino_attributes['project']

def get_domino_user_name(domino_attributes):
    token = domino_attributes['token']
    return get_user_name(token=token)


def read_auth_tokens(request:requests.Request):
    domino_attributes = parse_mlflow_token(read_mlflow_token(request))
    return domino_attributes
    '''
    if (authtoken.startswith("Basic ")):
        basic_auth = base64.b64decode(authtoken[6:])
        lst = basic_auth.decode("utf-8").split(":")
        user_name= lst[0]
        password = lst[1]
        ##Authenticate here
        return domino_authenticate(user_name,password)
    '''

def get_user_name(token='',user=''):
    if(len(token)>0): #Use Token Based Auth
        url = urljoin(os.environ['DOMINO_API_HOST'],who_am_i_endpoint)
        headers={'X-Domino-Api-Key':token}
        resp = requests.get(url, headers=headers)
        return resp.json()['canonicalName']
    else:
        user = 'wadkars'
        return user


s = 'test'
print(parse_mlflow_token(s))
