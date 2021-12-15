import sys
import os
import logging
from flask import Flask,request,redirect,Response
import requests
import logging

from jproperties import Properties

app = Flask(__name__)


@app.route('/')
def index():
    logging.info('Default Path ' + SITE_NAME)
    resp = requests.get(f'{SITE_NAME}')
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
    response = Response(resp.content, resp.status_code, headers)
    return response


@app.route('/<path:path>',methods=['GET','POST','DELETE'])
def proxy(path,**kwargs):
    global SITE_NAME
    logging.info('Default GET ' + SITE_NAME)
    logging.info('Default GET PATH ' + path)

    if request.method=='GET':
        url = f'{SITE_NAME}{path}'
        resp = requests.get(f'{SITE_NAME}{path}',params=request.args)
        logging.info(url)
        logging.info(resp)

        #excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        excluded_headers=[]
        headers = [(name, value) for (name, value) in  resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        return response
    elif request.method=='POST':
        my_json=request.get_json()



        if(path.endswith('runs/create')):


            if('tags' not in my_json ):
                response = Response('You must provide tag for mlflow.user', 400)
                return response
            else:
                tags = my_json['tags']
                for t in tags:
                    if(t['key']=='mlflow.user'):
                        if(t['value'] == user_name):
                            break
                        else:
                            response = Response('mlflow.user must be your own user.id', 400)
                            return response

        resp = requests.post(f'{SITE_NAME}{path}',json=my_json)
        #excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        excluded_headers = []
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        return response
    elif request.method=='DELETE':
        resp = requests.delete(f'{SITE_NAME}{path}').content
        response = Response(resp.content, resp.status_code)
    return response

def get_workspace_variables():
    global user_name
    global project_name
    global project_name
    configs = Properties()
    p = root_folder + '/etc/labels/' +  'labels'
    with open(p, 'rb') as read_prop:
        configs.load(read_prop)
        user_name = configs.get('dominodatalab.com/starting-user-username').data.replace('"','')
        project_name = configs.get('dominodatalab.com/starting-user-username').data.replace('"','')
        project_name = configs.get('dominodatalab.com/project-owner-username').data.replace('"','')




user_name=''
project_name=''
project_owner_name=''
root_folder=''

if __name__ == '__main__':
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
    get_workspace_variables()
    app.run(debug = False,port= port)


