import boto3
from os import getenv
from requests_aws4auth import AWS4Auth
import requests
import json
import logging

OPENSEARCH_HOST = getenv("OPENSEARCH_HOST")

REGION = getenv("AWS_REGION", "us-east-1")
SERVICE = "es"
URL = "https://" + OPENSEARCH_HOST

logger = logging.getLogger()
logger.setLevel(logging.INFO)

credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key,
                   REGION, SERVICE, session_token=credentials.token)


def handler(event, context):
    logger.info(f"Event: {event}")
    request_type = event["RequestType"]
    if request_type == "Create":
        return on_create(event)
    else:
        logger.error(f"Invalid/unhandled request type: {request_type}")


def on_create(event):
    logger.info(f"on_create event begin.\n Resource properties: {event['ResourceProperties']}")
    try:
        api_requests = event["ResourceProperties"]["api_requests"]
        physical_id = "OpensearchConfigPhysicalId"
        for api_request in api_requests:
            r = requests.request(api_request["method"],URL+api_request["path"],auth=awsauth,
                                 json=api_request["body"], timeout=60)
            logger.info(f"Opensearch config api response: {r.text}")
    except Exception as e: 
        logger.error(f"Failed to configure opensearch.\nError: {e}")

    return {"PhysicalResourceId": physical_id}
