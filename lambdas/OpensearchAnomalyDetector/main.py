import boto3
from os import getenv
import sys
from requests_aws4auth import AWS4Auth
import requests
from requests.adapters import HTTPAdapter, Retry
import json
import time
import logging

OPENSEARCH_HOST = getenv("OPENSEARCH_HOST")
OPENSEARCH_VERSION = getenv("OPENSEARCH_VERSION")
ENABLE_LAMBDA_TRAIL = getenv("ENABLE_LAMBDA_TRAIL")
SNS_TOPIC_ARN = getenv("SNS_TOPIC_ARN")
SNS_ALERT_ROLE = getenv("SNS_ALERT_ROLE")

REGION = getenv("AWS_REGION", "us-east-1")
SERVICE = "es"
URL = f"https://{OPENSEARCH_HOST}"

logger = logging.getLogger()
logger.setLevel(logging.INFO)

credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key,
                   REGION, SERVICE, session_token=credentials.token)

session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[ 400, 500, 502, 503, 504 ], allowed_methods=frozenset({"POST"}))
session.mount("https://", HTTPAdapter(max_retries=retries))

def handler(event, context):
    logger.info(f"Event: {event}")
    try:
        request_type = event["RequestType"]
        if request_type == "Create":
            time.sleep(300) # for log subscription to send logs to opensearch domain
            return on_create(event)
        else:
            logger.info(f"invalid/unhandled request type: {request_type}")
    except KeyError:
        return on_create(event)


def on_create(event):
    logger.info(f"on_create event begin.")
    physical_id = "OpensearchAnomalyDPhysicalId"

    opensearch_index_pattern_dashboard()
    
    if OPENSEARCH_VERSION.startswith("OPENSEARCH_1_"):
        email_destination_id = opensearch_alert_destination('usagedetector_alerting_email')
    elif OPENSEARCH_VERSION.startswith("OPENSEARCH_2_"):
        email_destination_id = opensearch_notification_channel("usagedetector_alerting_email")
    else:
        # defaulting to version 2.9
        email_destination_id = opensearch_notification_channel("usagedetector_alerting_email")

    try:
        with open("anomaly_detectors.json") as f:
            detectors = json.load(f)
    except OSError as oserr:
        logger.error(f"Could not open/read detectors file.\nError: {oserr}")
        sys.exit()

    for detector in detectors:
        if "category_field" in detector:
            for category_field in detector["category_field"]:
                opensearch_dummy_data(category_field.rsplit(".",1)[0],category_field.rsplit(".",1)[1])
        opensearch_anomaly_detector(detector,email_destination_id)
    
    return {"PhysicalResourceId": physical_id}

def opensearch_index_pattern_dashboard():
    # index-pattern & dasboards
    try:
        dashboard_file = {"file": open("usage_detector_dashboards.ndjson", "rb")}
    except OSError as oserr:
        logger.error(f"Could not open/read dashboard file.\nError: {oserr}")
        sys.exit()
    try:
        r = requests.post(f"{URL}/_dashboards/api/saved_objects/_import?overwrite=true", auth=awsauth,
                    headers={"osd-xsrf": "true", "securitytenant": "global"}, files=dashboard_file, timeout=60)
        logger.info(f"Dashboard import successful.\nDetails: {r.text}")
    except Exception as e:
        logger.error(f"Failed to import opensearch index-pattern & dashboards.\nError: {e}")
        sys.exit()
 
def opensearch_notification_channel(channel_name):
    try:
        r = requests.get(f"{URL}/_plugins/_notifications/configs", auth=awsauth, timeout=60)
        if len(r.json()["config_list"]) > 0:
            configs = r.json()["config_list"]
            for config in configs:
                if config["config"]["name"] == channel_name:
                    print(f"{channel_name} notification channel already exists!")
                    return config["config_id"]
        logger.info(f"Creating notification channel: {channel_name}")
        r = requests.post(f"{URL}/_plugins/_notifications/configs", auth=awsauth, json={
                          "name": channel_name, "config": {"name": channel_name, "description": "usage-anomaly-detector notifcation channel", "config_type":"sns", "sns": {"role_arn": SNS_ALERT_ROLE, "topic_arn": SNS_TOPIC_ARN}}}, timeout=60)
        logger.info(f"Created notification channel succesfully.\nDetails: {r.text}")

    except Exception as e:
        logger.error(f"failed to create notification channel config.\nError: {e}")
        sys.exit()
    
    return r.json()["config_id"]

def opensearch_alert_destination(destination_name):
    try:
        r = requests.get(URL + '/_plugins/_alerting/destinations', auth=awsauth, timeout=5)
        if r.status_code == 404:
            logger.info(f"Alerting destinations does not exist.")
        else:
            destinations = r.json()["destinations"]
            for destination in destinations:
                if destination["name"] == destination_name:
                    logger.info(f"{destination_name} destination already exists!")
                    return destination["id"]

        logger.info(f"Creating alert destination: {destination_name}")
        r = requests.post(URL + '/_plugins/_alerting/destinations', auth=awsauth, json={
                          "name": destination_name, "type": "sns", "sns": {"role_arn": SNS_ALERT_ROLE, "topic_arn": SNS_TOPIC_ARN}}, timeout=10)
        logger.info(f"Created alert destination successfully.\nDetails: {r.text}")
    except Exception as e:
        logger.error(f"Failed to create alert destination.\nError: {e}")
        sys.exit()
    return r.json()["_id"]

def opensearch_dummy_data(property_name,field_name):
    try:
        dummy_index_name = "cwl-dummy"
        existing_dummy_index = requests.get(f"{URL}/{dummy_index_name}", auth=awsauth, timeout=60)
        
        if existing_dummy_index.status_code == 404:
            create_dummy_index = requests.put(f"{URL}/{dummy_index_name}", auth=awsauth, timeout=60)
            create_dummy_index.raise_for_status()
            logger.info(f"Created dummy index: {dummy_index_name}")

        r = requests.put(f"{URL}/{dummy_index_name}/_mapping", auth=awsauth, json={"properties":{property_name:{"type":"text","fields":{field_name:{"type":"keyword"}}}}}, timeout=60)
        r.raise_for_status()
        logger.info(f"Added dummy data fields, index:{dummy_index_name}, field:{property_name}.{field_name}")

    except requests.exceptions.HTTPError as err:
        logger.error(f"Failed to create dummy data.\nError: {err}")
    
def opensearch_anomaly_detector(detector, email_destination_id):
    detector_name = detector["name"]
    if detector_name.startswith("lambda-"):
        if ENABLE_LAMBDA_TRAIL != "true":
            return
    
    try:
        existing_detectors = requests.post(f"{URL}/_plugins/_anomaly_detection/detectors/_search", auth=awsauth, 
                                           json={"query":{"wildcard":{"indices": {"value": "cwl*"}}}}, timeout=60)        
        
        if existing_detectors.status_code == 404:
            logger.info(f"Previous detector configuration does NOT exists.")
        else:
            logger.info(f"Previous detector configuration exists.\nDetails: {existing_detectors.text}")
            if existing_detectors.json()["hits"]["total"]["value"] > 0:
                for existing_detecor_names in existing_detectors.json()["hits"]["hits"]:
                    if detector_name == existing_detecor_names["_source"]["name"]:
                        logger.info(f"{detector_name} already exists, will skip creation!")
                        return
        
        logger.info(f"Creating detector: {detector}")
        create_detector = session.post(f"{URL}/_plugins/_anomaly_detection/detectors", auth=awsauth, 
                                 json=detector, timeout=60)
        create_detector.raise_for_status()
        detector_id = create_detector.json()["_id"]
        logger.info(f"Created detector: {detector_name}, detector_id: {detector_id}")

        if create_detector.status_code == 201: ## detector created
            detector_alert_config = {"name": detector_name+"-Monitor", "type": "monitor", "monitor_type": "query_level_monitor", "enabled": True, "schedule": {"period": {"unit": "MINUTES", "interval":10}},"inputs":[{"search":{"indices":[".opendistro-anomaly-results*"],"query":{"size":1,"sort":[{"anomaly_grade":"desc"},{"confidence":"desc"}],"query":{"bool":{"filter":[{"range":{"execution_end_time":{"from":"{{period_end}}||-20m","to":"{{period_end}}","include_lower":True,"include_upper":True}}},{"term":{"detector_id":{"value":detector_id}}}]}},"aggregations":{"max_anomaly_grade":{"max":{"field":"anomaly_grade"}}}}}}],"triggers":[{"query_level_trigger":{"name":detector_name+"-Trigger","severity":"1","condition":{"script":{"source":"return ctx.results != null && ctx.results.length > 0 && ctx.results[0].aggregations != null && ctx.results[0].aggregations.max_anomaly_grade != null && ctx.results[0].hits.total.value > 0 && ctx.results[0].hits.hits[0]._source != null && ctx.results[0].hits.hits[0]._source.confidence != null && ctx.results[0].aggregations.max_anomaly_grade.value != null && ctx.results[0].aggregations.max_anomaly_grade.value > 0.7 && ctx.results[0].hits.hits[0]._source.confidence > 0.7","lang":"painless"}},"actions":[{"name":detector_name+"Email-Notification","destination_id":email_destination_id,"message_template":{"source":"Monitor {{ctx.monitor.name}} just entered alert status. Please investigate the issue.\n  - Trigger: {{ctx.trigger.name}}\n  - Period start: {{ctx.periodStart}}\n  - Period end: {{ctx.periodEnd}}","lang":"mustache"},"throttle_enabled":False,"subject_template":{"source":detector_name+" Detector Alert","lang":"mustache"}}]}}]}
            r = requests.post(f"{URL}/_plugins/_alerting/monitors",auth=awsauth, 
                              json=detector_alert_config, timeout=60)
            logger.info(f"Created monitor: {detector_name}-Monitor for detector: {detector_name}, monitor_id: {r.json()['_id']}")

            r = requests.post(f"{URL}/_plugins/_anomaly_detection/detectors/{detector_id}/_start", auth=awsauth, timeout=60)
            logger.info(f"Started detector: {detector_id}, reponse: {r.text}")
        else:
            logger.error(f"Skipped monitor creation: {detector_name}-Monitor & detector: {detector_name} is NOT started. Check logs for details!")
    except requests.exceptions.HTTPError as err:
        logger.error(f"Failed to create detector: {detector['name']}. Error: {err}")

    return
