#mlflow_s3_based_access_control_mutation
#export MLFLOW_TRACKING_URI=http://localhost:8204/
export MLFLOW_TRACKING_URI="${MLFLOW_TRACKING_URI:-https://myfield_registry.com/}"
docker build --build-arg MLFLOW_TRACKING_URI=$MLFLOW_TRACKING_URI -f ./DockerfileAWSProxy -t quay.io/wadkars/mock-jit:awsv3 .
docker push quay.io/wadkars/mock-jit:awsv3

