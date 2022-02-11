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
s={'domino_api_key': '', 'domino_project_name': 'mlflow-demo', 'domino_run_id': '6205b52dd2cb0975f43cccaa'}
import access_control
x=access_control.encode_as_jwt('','mlflow-demo','6205816cd2cb0975f43cbb39')
os.environ['MLFLOW_TRACKING_TOKEN']=x

name = 'master213'
experiment_name=name
client = mlflow.tracking.MlflowClient(tracking_uri=TRACKING_URI)

experiment = client.get_experiment_by_name(name=experiment_name)
print(experiment)
if(experiment is None):
    print('Creating experiment ')
    client.create_experiment(name=experiment_name)
    experiment = client.get_experiment_by_name(name=name)
    print(experiment)
mlflow.set_tracking_uri(TRACKING_URI)
mlflow.set_experiment(experiment_name=experiment_name)



csv_url = (
     "http://archive.ics.uci.edu/ml/machine-learning-databases/wine-quality/winequality-red.csv"
)
data = pd.read_csv(csv_url, sep=";")

# Split the data into training and test sets. (0.75, 0.25) split.
train, test = train_test_split(data)

# The predicted column is "quality" which is a scalar from [3, 9]
train_x = train.drop(["quality"], axis=1)
test_x = test.drop(["quality"], axis=1)
train_y = train[["quality"]]
test_y = test[["quality"]]

alpha = 0.5
l1_ratio = 0.5
my_log = "This is a test log"
with open("/tmp/test.txt", 'w') as f:
    f.write(my_log)
with open("/tmp/test.log", 'w') as f:
    f.write(my_log)
def eval_metrics(actual, pred):
    rmse = np.sqrt(mean_squared_error(actual, pred))
    mae = mean_absolute_error(actual, pred)
    r2 = r2_score(actual, pred)
    return rmse, mae, r2


#Change user name
with mlflow.start_run(tags={'mlflow.user':'wadkars'}):
    lr = ElasticNet(alpha=alpha, l1_ratio=l1_ratio, random_state=42)
    lr.fit(train_x, train_y)
    predicted_qualities = lr.predict(test_x)

    (rmse, mae, r2) = eval_metrics(test_y, predicted_qualities)

    print("Elasticnet model (alpha=%f, l1_ratio=%f):" % (alpha, l1_ratio))
    print("  RMSE: %s" % rmse)
    print("  MAE: %s" % mae)
    print("  R2: %s" % r2)

    mlflow.log_param("alpha", alpha)
    mlflow.log_param("l1_ratio", l1_ratio)
    mlflow.log_metric("rmse", rmse)
    mlflow.log_metric("r2", r2)
    mlflow.log_metric("mae", mae)

    tracking_url_type_store = urlparse(mlflow.get_tracking_uri()).scheme
    print('XXX')
    print(mlflow.get_tracking_uri())
    print(tracking_url_type_store)
    # Model registry does not work with file store
#    if tracking_url_type_store != "file":
#        mlflow.sklearn.log_model(lr, "model", registered_model_name="DEMO2-ElasticnetWineModel")

#    else:

 #       mlflow.sklearn.log_model(lr, "model")
    #mlflow.log_artifact("/tmp/test.txt")
    #mlflow.log_artifact("/tmp/test.log")

experiment = client.get_experiment_by_name(experiment_name)
print(experiment.tags)