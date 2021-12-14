FROM quay.io/domino/python-public:3.8.7-slim
ADD requirements.txt .
ENV PATH=$PATH:/app/.local/bin:/app/bin
ENV PYTHONUNBUFFERED=true
ENV PYTHONUSERBASE=/home/app
ENV FLASK_ENV=production
ENV LOG_LEVEL=WARNING
RUN pip install --upgrade pip
RUN pip install --user -r requirements.txt
ADD src /app
RUN mkdir /tmp/domino
ARG MLFLOW_TRACKING_URI
#USER 1000
ENTRYPOINT ["python",  "/app/mlflow-auth-proxy.py" ,$MLFLOW_TRACKING_URI, "6010"]
