import os
import requests
import jwt
import mlflow

GET_PROJECTS_ENDPOINT = 'v4/projects'
GET_USERS_ENDPOINT = 'v4/users'
GET_CURRENT_USER_ENDPOINT = 'v4/users/self'
GET_PAST_RUNS_ENDPOINT = 'v4/gateway/runs/getByBatchId'
GET_CURRENT_RUNS_ENDPOINT = 'v4/runs/recent'
GET_AUTH_PRINCIPAL_ENDPOINT = 'v4/auth/principal'

runs_by_run_id={}

def get_domino_api_key():
    return os.getenv('DOMINO_ADMIN_API_KEY')

def get_domino_url():
    return 'https://fieldregistry.cs.domino.tech'

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
    url = os.path.join(get_domino_url(),GET_PAST_RUNS_ENDPOINT)
    response = requests.get(url,headers=headers)
    if(response.status_code==200):
        result = response.json()
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

def get_current_run_details():
    runs_by_run_id={}
    headers = {'X-Domino-Api-Key': get_domino_api_key()}
    url = os.path.join(get_domino_url(),GET_CURRENT_RUNS_ENDPOINT)
    response = requests.get(url,headers=headers)
    if(response.status_code==200):
        result = response.json()
        for run in result:
            current_run_tags = {}
            current_run_tags['project_id'] = run['projectId']
            current_run_tags['project_name'] = run['projectIdentity']
            current_run_tags['run_type'] = run['runType']
            current_run_tags['hardware_tier'] = run['hardwareTierName']
            current_run_tags['run_duration_in_seconds'] = run['runDurationInSeconds']
            current_run_tags['estimated_cost'] = run['estimatedCost']
            runs_by_run_id[run['id']]=current_run_tags
    return runs_by_run_id


def get_run_details(run_id):
    details = get_current_run_details()
    if run_id in details:
        return details[run_id]
    return {}

def get_experiment_rights(user_id,experiment_id,tags={}):
    #If Experiment and Projects are linked, return both
    #If Experiment is not linked to Project only Experiment rights matter

    return {'EXPERIMENT':[], 'PROJECT':[]}


def encode_as_jwt(domino_api_key,domino_project_name,domino_run_id):
    encoded_jwt = jwt.encode({"domino_api_key": domino_api_key,"domino_project_name":domino_project_name,
                              "domino_run_id":domino_run_id},
                              "secret", algorithm="HS256")
    return encoded_jwt

def decode_jwt(encoded_jwt=None):
    return jwt.decode(encoded_jwt, "secret", algorithms=["HS256"])


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

def is_user_authorized_for_run_updates(request_json):
    mlflow_client = mlflow.tracking.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)
    experiment = mlflow_client.get_experiment(request_json['experiment_id'])
    print(experiment.tags)
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

MLFLOW_TRACKING_URI=''
if __name__ == "__main__":
    import sys
    os.environ['DOMINO_URL'] = sys.argv[1]
    os.environ['DOMINO_ADMIN_API_KEY']=sys.argv[2]
    print(get_run_details('6203ebfcd2cb0975f43ca4fb'))
    print(encode_as_jwt('a','b','c'))
    print(decode_jwt(encode_as_jwt('a','b','c')))
    print(get_all_projects())
    print(get_all_users())
    print(get_user_auth(get_domino_api_key()))

    x = jwt.encode({"domino_api_key": 'a',"domino_project_name":'b',
                              "domino_run_id":'c'},
                              "secret", algorithm="HS256")
    t = x + 'vvv'
'''
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