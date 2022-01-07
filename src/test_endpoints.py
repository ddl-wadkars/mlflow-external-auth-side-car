import os
import mlflow
import mlflow.sklearn
import utils

TRACKING_URI = 'http://127.0.0.1:8000/'

def test_token_based_access():
    if 'MLFLOW_TRACKING_TOKEN' not in os.environ.keys():
        print('MLFLOW_TRACKING_TOKEN' + ' env variable must be set to the value of DOMINO API KEY')
    mlflow.tracking.set_tracking_uri(TRACKING_URI)
    lst = mlflow.list_experiments()
    print(lst)

def test_user_id_based_access():
    if ('MLFLOW_TRACKING_USERNAME' not in os.environ.keys() and 'MLFLOW_TRACKING_PASSWORD' not in os.environ.keys()):
        print('MLFLOW_TRACKING_USERNAME and MLFLOW_TRACKING_PASSWORD' + ' env variable must be set to the value user and password')
        return
    mlflow.tracking.set_tracking_uri(TRACKING_URI)
    lst = mlflow.list_experiments()
    print(lst)

domino_env = os.environ
print(domino_env)
print(domino_env['PATH'])
domino_api_host=domino_env['DOMINO_API_HOST'] #'https://fieldregistry.cs.domino.tech/'
domino_token=domino_env['DOMINO_USER_API_KEY']
print(domino_token)
domino_user=domino_env['DOMINO_STARTING_USERNAME']
domino_password=domino_env['DOMINO_PWD']

if __name__ == "__main__":

    user = utils.get_user_name(token=domino_token)
    print(user)

    print('Token based access')
    os.environ['MLFLOW_TRACKING_TOKEN'] = domino_token
    test_token_based_access()

    print('Basic authentication based access')
    os.environ['MLFLOW_TRACKING_USERNAME']='wadkars'
    os.environ['MLFLOW_TRACKING_PASSWORD'] = 'xxx'
    test_user_id_based_access()


