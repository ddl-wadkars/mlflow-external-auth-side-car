import sys
import os
import logging
from flask import Flask,request,redirect,Response
import requests
import logging
import json
from jproperties import Properties
import utils
from functools import wraps
from werkzeug.datastructures import ImmutableMultiDict
import mlflow
from collections import namedtuple
from flask_oidc import OpenIDConnect

app = Flask(__name__)
ADMIN_USER='wadkars'
app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': '/app/client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'DominoRealm',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OVERWRITE_REDIRECT_URI': 'https://fieldregistry.cs.domino.tech/mlflow/oidc_callback'
})
#oidc = OpenIDConnect(app)

'''
def authorize(view_func=None):
    @wraps(view_func)
    def decorated(*args, **kwargs):
        user_name=None
        user_name = utils.read_auth_tokens(request)
        #logging.info('User Name Found ' + user_name)
        logging.info('-----------------' )
        logging.info(user_name)
        if (user_name is None or user_name=='-'):
            logging.info('Require User Login In Browser')
            if(oidc.g==None):
                return oidc.redirect_to_auth_server('https://fieldregistry.cs.domino.tech/')
        return view_func(*args, **kwargs)
    return decorated
'''
@app.route('/')
#@oidc.require_login
def index():
    logging.info('Default Path ' + SITE_NAME)
    resp = requests.get(f'{SITE_NAME}')
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
    response = Response(resp.content, resp.status_code, headers)
    return response

def get_experiment_tags(tags):
    d={}
    for t in tags:
        d[t['key']]=t['value']
    return d

def access_control_for_get_experiments(path,params,resp,user_name):
    if (path.endswith('experiments/list')):
        resp_content_json = json.loads(resp.content)
        print(path)
        #return resp
        lst = []
        all_experiments = resp_content_json['experiments']
        for e in all_experiments:
            if('tags' in e):
                tags_dict = get_experiment_tags(e['tags'])
                if (user_name == ADMIN_USER):
                    lst.append(e)
                elif('domino.user' in tags_dict and 'domino.user' in tags_dict and tags_dict['domino.user']==user_name):
                    lst.append(e)
        resp_content_json['experiments']=lst
        s = json.dumps(resp_content_json)
        return s
    else:
        return ''




def validate_tags(path,my_json):
    if (path.endswith('runs/create')):
        tags = my_json['tags']
        user_found = False
        project_found = False
        for t in tags:
            if (t['key'] == 'mlflow.parentRunId'):
                user_found = True  # Nested runs do not check for user name consistency
                break

        for t in tags:
            if (t['key'] == 'mlflow.user' and not user_found):
                if (t['value'] == user_name):
                    user_found = True
                else:
                    return 'mlflow.user must be the current user = ' + user_name

            if (t['key'] == 'mlflow.project'):
                if (t['value'] == project_name):
                    project_found = True
                else:
                    return 'mlflow.project must be the current project = ' + project_name
        if (not user_found or not project_found):
            return 'You must provide correct tag values for mlflow.user and mlflow.project'
    return ''

def get_user_name(token):
    headers={'X-Domino-Api-Key':token}
    json = requests.get(os.environ['DOMINO_API_HOST']+who_am_i_endpoint, headers=headers)
    return json['canonicalName']
'''
def get_oauth_username():

    info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])

    username = info.get('preferred_username')
    return username
'''
def get_user_name(username,password):
    pass


def my_function_decorator(func):
    @wraps(func)
    def decorated_function(path, **kwargs):
        if(request.method=='POST' and request.path.path.endswith('experiment/create')):
            my_json = request.json.to_dict()
            my_json['tags']['test'] = 'test-tag'
            request.json = ImmutableMultiDict(my_json)
            return func(path, **kwargs)
        else:
            return func(path, **kwargs)
    return decorated_function



@app.route('/<path:path>',methods=['GET','POST','DELETE'])
#@oidc.require_login
def proxy(path,**kwargs):
    global SITE_NAME
    logging.info('Default GET ' + SITE_NAME)
    logging.info('Default GET PATH ' + path)
    logging.info(request)
    logging.info(request.headers)
    print(request.path)

    domino_attributes = utils.read_auth_tokens(request)
    print(domino_attributes)
    user_name = utils.get_domino_user_name(domino_attributes)
    project_name = utils.get_domino_project(domino_attributes)
    print('Returned user name ' + user_name)
    '''
    #user_name = get_oauth_username()

    
    if(user_name==None):
        logging.warning('Now REDIRECTING ' + request.url)
        oidc.redirect_to_auth_server()
    print(user_name)
    '''
    ##Read all tokens

    ##logging.info(request.headers)
    ##logging.info(json.dumps(request.headers))
    if request.method=='GET':
        url = f'{SITE_NAME}{path}'
        resp = requests.get(f'{SITE_NAME}{path}',params=request.args)
        content = access_control_for_get_experiments(path,request.args,resp,user_name)
        logging.info(url)
        '''
        Rewrite this function
        
        if (path.endswith('artifacts/list')):
            r = client.get_run(request.args['run_uuid'])
            exp = client.get_experiment(r.info.experiment_id)
            #la = client.list_artifacts(run_id=request.args['run_uuid'],path='model')
            la = client.list_artifacts(r.info.run_id,path='model')
            print(r.info.run_id)
            c = json.loads(resp.content)
            c['files'] = [{'path':'1.test','is_dir':False,'file_size':100 }]
            content = json.dumps(c)
        '''

        #excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        excluded_headers=[]
        headers = [(name, value) for (name, value) in  resp.raw.headers.items() if name.lower() not in excluded_headers]
        if(resp.status_code==500):
            print(resp.content)
        if(content==''):
            response = Response(resp.content, resp.status_code, headers)
        else:
            response = Response(content, resp.status_code, headers)
        return response
    elif request.method=='POST':
        my_json = request.json
        error_str = validate_tags(path,request.get_json())
        if(not error_str==''):
            response = Response(error_str, 400)
        resp = requests.post(f'{SITE_NAME}{path}',json=my_json)
        #excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        excluded_headers = []
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        if (path.endswith('experiments/create') and response.status_code==200):
            print('Setting domino user ' + user_name)
            client.set_experiment_tag(response.get_json()['experiment_id'],'domino.user',user_name)
            if (not project_name==''):
                client.set_experiment_tag(response.get_json()['experiment_id'], 'domino.project', project_name)
        return response
    elif request.method=='DELETE':
        resp = requests.delete(f'{SITE_NAME}{path}').content
        response = Response(resp.content, resp.status_code)
    return response


client=None
SITE_NAME = "http://fieldregistry.cs.domino.tech/mlflow/"
user_name=''
project_name=''
project_owner_name=''
root_folder=''
who_am_i_endpoint = 'v4/auth/principal'

if __name__ == '__main__':
    print(os.getcwd())
    port = 8000
    if(len(sys.argv)==1):
        SITE_NAME="http://fieldregistry.cs.domino.tech/mlflow/"
        root_folder = os.getcwd() + '/../root/'
        print('Root folder ' + root_folder)
    else:
        SITE_NAME = sys.argv[1]
        print('Starting proxy to ' + SITE_NAME)
        root_folder = sys.argv[2]
        print('Root folder ' + root_folder)
        logs_file = os.path.join(root_folder+'/var/log/app.log')

        logging.basicConfig(filename=logs_file, filemode='a', format='%(asctime)s - %(message)s',
                            level=logging.INFO, datefmt="%H:%M:%S")

        port = 8000
        if(len(sys.argv)>3):
            port = int(sys.argv[3])
        print('Starting proxy on port ' + str(8000))

    client = mlflow.tracking.MlflowClient(tracking_uri=SITE_NAME)

    app.run(debug = False,port= port, host="0.0.0.0")


