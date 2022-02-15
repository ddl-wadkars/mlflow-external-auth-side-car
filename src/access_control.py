import os
import requests
import jwt
import mlflow
import requests
from flask import Flask, request, redirect, Response
from flask.globals import  *
from urllib.parse import urljoin
WHO_AM_I_ENDPOINT = 'v4/auth/principal'

GET_PROJECTS_ENDPOINT = 'v4/projects'
GET_USERS_ENDPOINT = 'v4/users'
GET_CURRENT_USER_ENDPOINT = 'v4/users/self'
GET_PAST_RUNS_ENDPOINT = 'v4/gateway/runs/getByBatchId'
GET_CURRENT_RUNS_ENDPOINT = 'v4/runs/recent'
GET_AUTH_PRINCIPAL_ENDPOINT = 'v4/auth/principal'
GET_PROJECT_ENDPOINT =  'v4/projects'
runs_by_run_id={}

def get_domino_api_key():
    return os.getenv('DOMINO_ADMIN_API_KEY')

def get_domino_url():
    return DOMINO_NUCLEUS_URI

def can_i_create_experiment(user_name):
    return True

def can_i_delete_experiment(user_name):
    return True

def can_i_create_run(experiment_id):
    return True

def can_i_view_artifacts(run_id):
    return True

def am_i_a_collaborator(project_id):
    return True

def am_i_a_owner(project_id):
    return True

def am_i_a_results_consumer(project_id):
    return True

def get_project_details(project_id):
    return {}

def get_all_projects():
    headers = {'X-Domino-Api-Key': get_domino_api_key()}
    url = os.path.join(get_domino_url(),GET_PROJECTS_ENDPOINT)
    ret = requests.get(url, headers=headers)
    projects = ret.json()
    return projects

def get_all_users():
    headers = {'X-Domino-Api-Key': get_domino_api_key()}
    url = os.path.join(get_domino_url(),GET_USERS_ENDPOINT)
    ret = requests.get(url, headers=headers)
    users = ret.json()
    return users

def get_current_user(user_api_key):
    headers = {'X-Domino-Api-Key': user_api_key}
    url = os.path.join(get_domino_url(),GET_CURRENT_USER_ENDPOINT)
    ret = requests.get(url, headers=headers)
    users = ret.json()
    return users

def get_user_auth(user_api_key):
    headers = {'X-Domino-Api-Key': user_api_key}
    url = os.path.join(get_domino_url(),GET_AUTH_PRINCIPAL_ENDPOINT)
    ret = requests.get(url, headers=headers)
    users = ret.json()
    return users



def get_past_run_details():
    runs_by_run_id={}
    headers = {'X-Domino-Api-Key': get_domino_api_key()}
    print('xx')
    print(headers)
    url = os.path.join(get_domino_url(),GET_PAST_RUNS_ENDPOINT)
    response = requests.get(url,headers=headers)
    if(response.status_code==200):
        result = response.json()
        print(result)
        for run in result['runs']:
            current_run_tags = {}
            current_run_tags['project_id'] = run['projectId']
            current_run_tags['project_name'] = run['projectName']
            current_run_tags['run_type'] = run['runType']
            current_run_tags['hardware_tier'] = run['hardwareTier']
            current_run_tags['run_duration_in_seconds'] = run['runDurationSec']
            current_run_tags['estimated_cost'] = run['hardwareTierCostAmount']
            runs_by_run_id[run['runId']]=current_run_tags
        return runs_by_run_id

def get_current_run_details(user_api_key):
    runs_by_run_id={}
    headers = {'X-Domino-Api-Key': user_api_key}
    url = os.path.join(get_domino_url(),GET_CURRENT_RUNS_ENDPOINT)
    response = requests.get(url,headers=headers)
    if(response.status_code==200):
        result = response.json()
        for run in result:

            current_run_tags = {}
            current_run_tags['id'] = run['id']
            current_run_tags['project_id'] = run['projectId']
            current_run_tags['project_name'] = run['projectIdentity']
            current_run_tags['run_type'] = run['runType']
            current_run_tags['hardware_tier'] = run['hardwareTierName']
            current_run_tags['run_duration_in_seconds'] = run['runDurationInSeconds']
            current_run_tags['estimated_cost'] = run['estimatedCost']
            runs_by_run_id[run['id']]=current_run_tags
    return runs_by_run_id


def get_run_details(user_api_key,run_id):
    details = get_current_run_details(user_api_key)
    if run_id in details:
        return details[run_id]
    return None

def get_experiment_rights(user_id,experiment_id,tags={}):
    #If Experiment and Projects are linked, return both
    #If Experiment is not linked to Project only Experiment rights matter

    return {'EXPERIMENT':[], 'PROJECT':[]}
'''
def domino_mlflow_init(domino_api_key=os.environ['DOMINO_USER_API_KEY'],domino_project_name=os.environ['DOMINO_PROJECT_NAME'],domino_run_id=os.environ['DOMINO_RUN_ID']):
    encoded_jwt = jwt.encode({"domino_api_key": domino_api_key,"domino_project_name":domino_project_name,
                              "domino_run_id":domino_run_id},
                              "secret", algorithm="HS256")
    os.environ['MLFOW_TRACKING_TOKEN']=encoded_jwt.decode()
'''
def encode_as_jwt(domino_api_key,domino_project_name='',domino_run_id=''):
    encoded_jwt = jwt.encode({"domino_api_key": domino_api_key,"domino_project_name":domino_project_name,
                              "domino_run_id":domino_run_id},
                              "secret", algorithm="HS256")

    return encoded_jwt.decode()

def get_mlflow_token():
    encoded_jwt = jwt.encode({"domino_api_key": os.environ['DOMINO_USER_API_KEY'],"domino_project_name":os.environ['DOMINO_PROJECT_NAME'],
                              "domino_run_id":os.environ['DOMINO_RUN_ID']},
                              "secret", algorithm="HS256")
    return encoded_jwt.decode()
def decode_jwt(encoded_jwt=None):
    return jwt.decode(encoded_jwt.encode(), "secret", algorithms=["HS256"])


def get_run_user(mlflow_client,request_json):
    if('tags' in request_json):
        tags = request_json['tags']
        mlflow_user=''
        for t in tags:
            if (t['key'] == 'mlflow.user'):
                mlflow_user = t['value']
                break

        for t in tags:
            if (t['key'] == 'mlflow.parentRunId'):
                run = mlflow_client.get_run(mlflow.parentRunId)
                mlflow_user = run.data.tags['mlflow.user']
                break
        return mlflow_user

def is_user_authorized_for_get(api_token,path,request_json):
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)
    experiment,run = get_experiment_and_run(api_token,request_json)
    user_roles_by_project = get_domino_user_roles_by_project(api_token)
    #Now do something
    if(path.endswith('mlflow/experiments/list')):
        pass

    return True
def is_user_authorized_mlflow(api_token,path,request:Request):
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)
    experiment,run = get_experiment_and_run(api_token,request.json)
    user_roles_by_project = get_domino_user_roles_by_project(api_token)
    mlflow_response:Response=None
    if(request.method=='GET'):
        mlflow_response = requests.get(f'{MLFLOW_TRACKING_URI}{path}', params=request.args)
    if(request.method=='POST'):
        mlflow_response = requests.post(f'{MLFLOW_TRACKING_URI}{path}', json=request.json)
    if(request.method=='DELETE'):
        mlflow_response = requests.delete(f'{MLFLOW_TRACKING_URI}{path}', json=request.json)
    if(request.method=='PATCH'):
        mlflow_response = requests.patch(f'{MLFLOW_TRACKING_URI}{path}', json=request.json)

    #Now do something ß
    if(path.endswith('mlflow/experiments/list')):
        pass
    elif(path.endswith('mlflow/experiments/create')):
        pass
    elif(path.endswith('mlflow/experiments/get') or
         path.endswith('mlflow/experiments/get-by-name') or
         path.endswith('mlflow/experiments/delete') or
         path.endswith('mlflow/experiments/update') or
         path.endswith('mlflow/experiments/restore') or
         path.endswith('mlflow/experiments/set-experiment-tag')):
        pass
    elif(path.endswith('mlflow/runs/create') or
         path.endswith('mlflow/runs/delete') or
         path.endswith('mlflow/runs/restore') or
         path.endswith('mlflow/runs/get') or
         path.endswith('mlflow/runs/log-metric') or
         path.endswith('mlflow/runs/log-batch') or
         path.endswith('mlflow/runs/log-model') or
         path.endswith('mlflow/runs/log-model') or
         path.endswith('mlflow/runs/set-tag') or
         path.endswith('mlflow/runs/delete-tag') or
         path.endswith('mlflow/runs/log-parameter') or
         path.endswith('mlflow/runs/log-parameter')):
        pass
    elif(path.endswith('mlflow/runs/create') or
         path.endswith('mlflow/runs/delete') or
         path.endswith('mlflow/runs/restore') or
         path.endswith('mlflow/runs/get') or
         path.endswith('mlflow/runs/log-metric') or
         path.endswith('mlflow/runs/log-batch') or
         path.endswith('mlflow/runs/log-model') or
         path.endswith('mlflow/runs/log-model') or
         path.endswith('mlflow/runs/set-tag') or
         path.endswith('mlflow/runs/delete-tag') or
         path.endswith('mlflow/runs/log-parameter') or
         path.endswith('mlflow/runs/log-parameter') or
         path.endswith('mlflow/metrics/get-history') or
         path.endswith('mlflow/runs/search') or
         path.endswith('mlflow/artifacts/list') or
         path.endswith('mlflow/runs/update') or
         path.endswith('mlflow/runs/update')):
        pass
    elif(path.endswith('mlflow/registered-models/create') or
         path.endswith('mlflow/registered-models/get') or
         path.endswith('mlflow/registered-models/rename') or
         path.endswith('mlflow/registered-models/update') or
         path.endswith('mlflow/registered-models/delete') or
         path.endswith('mlflow/registered-models/list') or ##Only list models and  versions you are allowed to see
         path.endswith('mlflow/registered-models/get-latest-versions') or
         path.endswith('mlflow/registered-models/search') or
         path.endswith('mlflow/registered-models/set-tag') or
         path.endswith('mlflow/registered-models/set-tag') or
         path.endswith('mlflow/registered-models/delete-tag')):
        pass
    elif(path.endswith('mlflow/model-versions/create') or
         path.endswith('mlflow/model-versions/get') or
         path.endswith('mlflow/model-versions/update') or
         path.endswith('mlflow/model-versions/search') or
         path.endswith('mlflow/model-versions/get-download-uri') or
         path.endswith('mlflow/model-versions/transition-stage') or #This is how it moves to production
         path.endswith('mlflow/model-versions/set-tag') or
         path.endswith('mlflow/model-versions/delete-tag')):
        pass
    else:
        pass #Throw 403 exception
    return True



def get_experiment_and_run(api_token, request_json):
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)
    experiment = None
    run = None
    if('experiment_id' in request_json):
        experiment = mlflow_client.get_experiment(request_json['experiment_id'])
    if ('run_id' in request_json):
        run  = mlflow_client.get_run(request_json['run_id'])
        experiment =  mlflow_client.get_experiment(run.info.experiment_id)

    return experiment,run




def is_user_authorized_for_run_updates(request_json):
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)
    experiment = mlflow_client.get_experiment(request_json['experiment_id'])
    run_user = get_run_user(mlflow_client,request_json)
    if (experiment.tags['domino.user'] != run_user):
        return False
    return True
def is_user_owner_of_experiment(experiment_name,user_name):
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)
    experiment = mlflow_client.get_experiment_by_name(experiment_name)
    if (experiment.tags['domino.user'] != user_name):
        return False
    return True
def is_user_owner_of_artifacts(run_id,user_name):
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)
    r = mlflow_client.get_run(run_id)
    experiment = mlflow_client.get_experiment(r.info.experiment_id)
    if (experiment.tags['domino.user'] != user_name):
        return False
    return True


def read_mlflow_token(request:requests.Request):
    if('Authorization' not in request.headers):
        return {'domino_api_key':'','domino_project_name':'','domino_run_id':''}
    else:
        authtoken = request.headers['Authorization']
        mlflow_token = authtoken[7:]
        return decode_jwt(mlflow_token)


def get_domino_user_name(token=''):
    if(len(token)>0): #Use Token Based Auth
        url = urljoin(os.environ['DOMINO_API_HOST'],WHO_AM_I_ENDPOINT)
        headers={'X-Domino-Api-Key':token}
        resp = requests.get(url, headers=headers)
        return resp.json()['canonicalName']
    else:
        user = '-'
        return user

def get_domino_user_roles_by_project(token=''):
    roles_by_project = {}
    user_id='-'

    user_roles = {id: user_id, 'roles_by_project': roles_by_project}
    if(len(token)>0): #Use Token Based Auth
        url = urljoin(os.environ['DOMINO_API_HOST'],WHO_AM_I_ENDPOINT)
        headers={'X-Domino-Api-Key':token}
        resp = requests.get(url, headers=headers)
        user_id =  resp.json()['canonicalId']
        url = urljoin(os.environ['DOMINO_API_HOST'], GET_PROJECT_ENDPOINT)
        response = requests.get(url, headers=headers)
        print(url)
        roles_by_project={}
        if(response.status_code==200):
            projects = response.json()
            for p in projects:
                project_id = p['id']
                if(user_id==p['ownerId']):
                    roles_by_project[project_id] = 'Owner'
                else:
                    collaborators = p['collaborators']
                    for c in collaborators:
                        collaborator_id=c['collaboratorId']
                        if(collaborator_id==user_id):
                            roles_by_project[project_id]=c['projectRole']
            user_roles = {'id': user_id, 'roles_by_project': roles_by_project}
    return user_roles


def configure_experiment_tags(user_api_key,path,experiment_json,user_name,project_name,run_id):
    if(not path.endswith('experiments/create')):
        return
    print(experiment_json)
    experiment_id = experiment_json['experiment_id']
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)

    mlflow_client.set_experiment_tag(experiment_id, 'domino.user', user_name)
    if (not project_name == ''):
        mlflow_client.set_experiment_tag(experiment_id, 'domino.project', project_name)
    print(run_id)
    if (not run_id == ''):
        r = get_run_details(user_api_key,run_id)
        if(r is not None):
            mlflow_client.set_experiment_tag(experiment_id, 'domino.run_id', run_id)
            mlflow_client.set_experiment_tag(experiment_id, 'domino.project_id', r['project_id'])
            mlflow_client.set_experiment_tag(experiment_id, 'domino.project_identity', r['project_name'])
            mlflow_client.set_experiment_tag(experiment_id, 'domino.run_type', r['run_type'])
            mlflow_client.set_experiment_tag(experiment_id, 'domino.hardware_tier', r['hardware_tier'])
            mlflow_client.set_experiment_tag(experiment_id, 'domino.run_duration_in_seconds', r['run_duration_in_seconds'])
            mlflow_client.set_experiment_tag(experiment_id, 'domino.estimated_cost', r['estimated_cost'])

def configure_run_tags(user_api_key,path,run_json,user_name,project_name,domino_run_id):
    print('creating run tags')
    if(not path.endswith('runs/create')):
        return
    mlflow_run_id = run_json['run']['info']['run_id']
    print(mlflow_run_id)
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)

    mlflow_client.set_tag(mlflow_run_id, 'domino.user', user_name)
    if (not project_name == ''):
        mlflow_client.set_tag(mlflow_run_id, 'domino.project', project_name)
    if (not domino_run_id == ''):
        r = get_run_details(user_api_key,domino_run_id)
        print(r)
        if(r is not None):
            mlflow_client.set_tag(mlflow_run_id, 'domino.run_id', domino_run_id)
            mlflow_client.set_tag(mlflow_run_id, 'domino.project_id', r['project_id'])
            mlflow_client.set_tag(mlflow_run_id, 'domino.project_identity', r['project_name'])
            mlflow_client.set_tag(mlflow_run_id, 'domino.run_type', r['run_type'])
            mlflow_client.set_tag(mlflow_run_id, 'domino.hardware_tier', r['hardware_tier'])
            mlflow_client.set_tag(mlflow_run_id, 'domino.run_duration_in_seconds', r['run_duration_in_seconds'])
            mlflow_client.set_tag(mlflow_run_id, 'domino.estimated_cost', r['estimated_cost'])

def get_user_role(user_id,experiment):
    return []



DOMINO_NUCLEUS_URI='http://nucleus-frontend.domino-platform:80'
#DOMINO_NUCLEUS_URI='https://fieldregistry.cs.domino.tech/'
MLFLOW_TRACKING_URI=''
os.environ['DOMINO_ADMIN_API_KEY']='412748c2003ff293acc416f53b3e9e6af8cb968cd91b1df4fc89c4e7c4105701'
if __name__ == "__main__":
    import sys
    os.environ['DOMINO_API_HOST'] ="https://fieldregistry.cs.domino.tech/"
    os.environ['DOMINO_ADMIN_API_KEY']=sys.argv[1]

    #jwt = encode_as_jwt(domino_api_key='412748c2003ff293acc416f53b3e9e6af8cb968cd91b1df4fc89c4e7c4105701')
    #print(jwt)
    #key=decode_jwt(jwt)
    #print(decode_jwt(key))
    #print(get_run_details('6203ebfcd2cb0975f43ca4fb'))
    #print(encode_as_jwt('a','b','c'))
    #print(decode_jwt(encode_as_jwt('a','b','c')))
    #print(get_all_projects())
    #print(get_all_users())
    api_key='412748c2003ff293acc416f53b3e9e6af8cb968cd91b1df4fc89c4e7c4105701'
    print(get_domino_user_roles_by_project(api_key))
    '''
    x = jwt.encode({"domino_api_key": 'a',"domino_project_name":'b',
                              "domino_run_id":'c'},
                              "secret", algorithm="HS256")
    t = x + 'vvv'

    Can be the following
    EXPERIMENT_OWNER
    EXPERIMENT_REVIEWER
    PROJECT_OWNER
    PROJECT_COLLABORATOR
    PROJECT_RESULTS_CONSUMER
    '''
    '''
    Basic rules:
    User needs to valid domino user to create experiments. Therefore any Domino user can create their own experiment
    Only the owner of the experiment can create runs inside an experiment (Does not apply to child runs but the parent run 
    must have the same owner as the child)
    ResultsConsumer can view experiements for a project but cannot create runs in them
    Collaborator/Owner can create runs inside a project
    
    
    User needs to be a librarian to see all experiments 
    "allowedSystemOperations": [
            "ManageProjectTags",
            "ListAllProjects",
            "PreviewProjects",
            "CurateProjects"
        ]
        
    Only the owner can view the artifacts
    '''