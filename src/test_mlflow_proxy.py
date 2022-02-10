import mlflow
from sklearn.linear_model import ElasticNet
import os
import warnings
import sys

import pandas as pd
import numpy as np
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from sklearn.model_selection import train_test_split
from sklearn.linear_model import ElasticNet
from urllib.parse import urlparse
import mlflow
import mlflow.sklearn

import logging


TRACKING_URI = 'http://127.0.0.1:8000/'
client = mlflow.tracking.MlflowClient(tracking_uri=TRACKING_URI)
mlflow.tracking.set_tracking_uri(TRACKING_URI)
s={'domino_api_key': '29577d27b1d1b29354fb9e9709a6f6b350faca3499fb0a5d33249d8c582865d0', 'domino_project_name': 'mlflow-demo', 'domino_run_id': '62052056d2cb0975f43ca88c'}
import access_control
x=access_control.encode_as_jwt('29577d27b1d1b29354fb9e9709a6f6b350faca3499fb0a5d33249d8c582865d0','mlflow-demo','6205816cd2cb0975f43cbb39')
os.environ['MLFLOW_TRACKING_TOKEN']=x

name = 'master27'
experiment_name=name
client = mlflow.tracking.MlflowClient(tracking_uri=TRACKING_URI)

experiment = client.get_experiment_by_name(name=experiment_name)
print(experiment)
if(experiment is None):
    print('Creating experiment ')
    client.create_experiment(name=experiment_name)
    experiment = client.get_experiment_by_name(name=name)
mlflow.set_tracking_uri(TRACKING_URI)
mlflow.set_experiment(experiment_name=experiment_name)

