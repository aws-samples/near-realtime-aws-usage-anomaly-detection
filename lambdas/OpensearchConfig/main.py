import boto3
from os import getenv
from requests_aws4auth import AWS4Auth
import requests
import json

OPENSEARCH_HOST = getenv('OPENSEARCH_HOST')

REGION = getenv('AWS_REGION', 'us-east-1')
SERVICE = 'es'
URL = 'https://' + OPENSEARCH_HOST

credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key,
                   REGION, SERVICE, session_token=credentials.token)


def handler(event, context):
    print(event)
    request_type = event['RequestType']
    if request_type == 'Create':
        return on_create(event)
    else:
        print('invalid/unhandled request type: {request_type}'.format(request_type=request_type))


def on_create(event):
    print('on_create event')
    print(event['ResourceProperties'])
    try:
        api_requests = event['ResourceProperties']['api_requests']
        physical_id = 'OpensearchConfigPhysicalId'
        for api_request in api_requests:
            r = requests.request(api_request["method"],URL+api_request["path"],auth=awsauth,json=api_request["body"], timeout=10)
            print(r.text)
    except Exception as e: 
        print('failed to configure opensearch. Error: {err}'.format(err=e))

    return {'PhysicalResourceId': physical_id}
