## How do I run this proxy

- Start the proxy on port 8000 (default port). Make sure to add your field registry endpoint. 
```shell
#Ex. Do not forget the trailing slash
#export MLFLOW_TRACKING_URI=http://localhost:8204/
export MLFLOW_TRACKING_URI="${MLFLOW_TRACKING_URI:-https://myfield_registry.com/}"
export MLFLOW_PORT="${MLFLOW_PORT:-8000}"
python src/mlflow-auth-proxy.py $MLFLOW_TRACKING_URL $MLFLOW_PORT
```
