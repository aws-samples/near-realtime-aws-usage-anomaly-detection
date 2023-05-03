import boto3
from os import getenv
import sys
from requests_aws4auth import AWS4Auth
import requests
from requests.adapters import HTTPAdapter, Retry
import json

OPENSEARCH_HOST = getenv('OPENSEARCH_HOST')
ENABLE_LAMBDA_TRAIL = getenv('ENABLE_LAMBDA_TRAIL')
SNS_TOPIC_ARN = getenv('SNS_TOPIC_ARN')
SNS_ALERT_ROLE = getenv('SNS_ALERT_ROLE')

REGION = getenv('AWS_REGION', 'us-east-1')
SERVICE = 'es'
URL = 'https://' + OPENSEARCH_HOST

credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key,
                   REGION, SERVICE, session_token=credentials.token)

s = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[ 400, 500, 502, 503, 504 ], allowed_methods=frozenset({'POST'}))
s.mount('https://', HTTPAdapter(max_retries=retries))

def handler(event, context):
    print(event)
    try:
        request_type = event['RequestType']
        if request_type == 'Create':
            return on_create(event)
        else:
            print('invalid/unhandled request type: {request_type}'.format(request_type=request_type))
    except KeyError:
        return on_create(event)


def on_create(event):
    print('on_create event')
    physical_id = 'OpensearchAnomalyDPhysicalId'

    opensearch_index_pattern_dashboard()
    
    email_destination_id = opensearch_alert_destination('usagedetector_alerting_email')

    try:
        with open('anomaly_detectors.json') as f:
            detectors = json.load(f)
    except OSError:
        print('Could not open/read detectors file, check logs!')
        sys.exit()

    for detector in detectors:
        if 'category_field' in detector:
            for category_field in detector['category_field']:
                opensearch_dummy_data(category_field.rsplit('.',1)[0],category_field.rsplit('.',1)[1])
        opensearch_anomaly_detector(detector,email_destination_id)
    
    return {'PhysicalResourceId': physical_id}

def opensearch_index_pattern_dashboard():
    # index-pattern & dasboards
    try:
        dashboard_file = {'file': open('usage_detector_dashboards.ndjson', 'rb')}
    except OSError:
        print('Could not open/read dashboard file, check logs!')
        sys.exit()
    try:
        r = requests.post(URL + '/_dashboards/api/saved_objects/_import?overwrite=true', auth=awsauth,
                    headers={"osd-xsrf": "true", "securitytenant": "global"}, files=dashboard_file, timeout=10)
        print(r.text)
    except Exception as e:
        print('failed to import opensearch index-patter & dashboards. Error: {err}'.format(err=e))
        sys.exit()
 
def opensearch_alert_destination(destination_name):
    try:
        r = requests.get(URL + '/_plugins/_alerting/destinations', auth=awsauth, timeout=5)
        if r.status_code == 404:
            print('alerting destinations does not exist.')
        else:
            destinations = r.json()["destinations"]
            for destination in destinations:
                if destination["name"] == destination_name:
                    print('{name} destination already exists!'.format(name=destination_name))
                    return destination["id"]

        print('creating alert destination: {name}'.format(name=destination_name))
        r = requests.post(URL + '/_plugins/_alerting/destinations', auth=awsauth, json={
                          "name": destination_name, "type": "sns", "sns": {"role_arn": SNS_ALERT_ROLE, "topic_arn": SNS_TOPIC_ARN}}, timeout=10)
        print(r.text)
    except Exception as e:
        print('failed to create alert destination. Error: {err}'.format(err=e))
        sys.exit()
    return r.json()["_id"]

def opensearch_dummy_data(property_name,field_name):
    try:
        dummy_index_name = 'cwl-dummy'
        existing_dummy_index = requests.get(URL+'/'+dummy_index_name, auth=awsauth, timeout=5)
        
        if existing_dummy_index.status_code == 404:
            create_dummy_index = requests.put(URL+'/'+dummy_index_name, auth=awsauth, timeout=5)
            create_dummy_index.raise_for_status()
            print('created dummy index: {name}'.format(name=dummy_index_name))

        r = requests.put(URL + '/'+dummy_index_name+'/_mapping', auth=awsauth, json={"properties":{property_name:{"type":"text","fields":{field_name:{"type":"keyword"}}}}}, timeout=10)
        r.raise_for_status()
        print('added dummy data fields, index:{idx}, field:{field}'.format(idx=dummy_index_name,field=property_name+'.'+field_name))
    except requests.exceptions.HTTPError as err:
        print('failed to create dummy data, please check logs! Error: {err}'.format(err=err))
    

def opensearch_anomaly_detector(detector, email_destination_id):
    detector_name = detector["name"]
    if detector_name.startswith("lambda-"):
        if ENABLE_LAMBDA_TRAIL != 'true':
            return
    
    try:
        existing_detectors = requests.post(URL + '/_plugins/_anomaly_detection/detectors/_search', auth=awsauth, json={"query":{"wildcard":{"indices": {"value": "cwl*"}}}}, timeout=10)        
        
        if existing_detectors.status_code == 404:
            print('Previous detector configuration does NOT exists!')
        else:
            print('Previous detector configuration exists! Details: {r}'.format(r=existing_detectors.text))
            if existing_detectors.json()["hits"]["total"]["value"] > 0:
                for existing_detecor_names in existing_detectors.json()["hits"]["hits"]:
                    if detector_name == existing_detecor_names["_source"]["name"]:
                        print('{detectorName} already exists, will skip creation!'.format(detectorName=detector_name))
                        return
        
        print('creating detector: {detector}'.format(detector=detector))
        create_detector = s.post(URL + '/_plugins/_anomaly_detection/detectors', auth=awsauth, json=detector, timeout=10)
        create_detector.raise_for_status()
        detector_id = create_detector.json()['_id']
        print('created detector: {detectorName}, detector_id: {detectorId}.'.format(
            detectorName=detector_name, detectorId=detector_id))

        if create_detector.status_code == 201: ## detector created
            detector_alert_config = {"name": detector_name+"-Monitor", "type": "monitor", "monitor_type": "query_level_monitor", "enabled": True, "schedule": {"period": {"unit": "MINUTES", "interval":10}},"inputs":[{"search":{"indices":[".opendistro-anomaly-results*"],"query":{"size":1,"sort":[{"anomaly_grade":"desc"},{"confidence":"desc"}],"query":{"bool":{"filter":[{"range":{"execution_end_time":{"from":"{{period_end}}||-20m","to":"{{period_end}}","include_lower":True,"include_upper":True}}},{"term":{"detector_id":{"value":detector_id}}}]}},"aggregations":{"max_anomaly_grade":{"max":{"field":"anomaly_grade"}}}}}}],"triggers":[{"query_level_trigger":{"name":detector_name+"-Trigger","severity":"1","condition":{"script":{"source":"return ctx.results != null && ctx.results.length > 0 && ctx.results[0].aggregations != null && ctx.results[0].aggregations.max_anomaly_grade != null && ctx.results[0].hits.total.value > 0 && ctx.results[0].hits.hits[0]._source != null && ctx.results[0].hits.hits[0]._source.confidence != null && ctx.results[0].aggregations.max_anomaly_grade.value != null && ctx.results[0].aggregations.max_anomaly_grade.value > 0.7 && ctx.results[0].hits.hits[0]._source.confidence > 0.7","lang":"painless"}},"actions":[{"name":detector_name+"Email-Notification","destination_id":email_destination_id,"message_template":{"source":"Monitor {{ctx.monitor.name}} just entered alert status. Please investigate the issue.\n  - Trigger: {{ctx.trigger.name}}\n  - Period start: {{ctx.periodStart}}\n  - Period end: {{ctx.periodEnd}}","lang":"mustache"},"throttle_enabled":False,"subject_template":{"source":detector_name+" Detector Alert","lang":"mustache"}}]}}]}
            r = requests.post(URL + '/_plugins/_alerting/monitors',
                                auth=awsauth, json=detector_alert_config, timeout=10)
            print('created monitor: {monitorName} for detector: {detectorName}, monitor_id: {monitorId}'.format(
                monitorName=detector_name+"-Monitor", detectorName=detector_name, monitorId=r.json()["_id"]))

            r = requests.post(URL + '/_plugins/_anomaly_detection/detectors/{detectorId}/_start'.format(
                                detectorId=detector_id), auth=awsauth, timeout=10)
            print('started detector: {detectorId}, reponse: {r}'.format(detectorId=detector_id,r=r.text))
        else:
            print('Skipped monitor creation: {name} & detector: {detectorName} is NOT started. Check logs for details!'.format(
                    name=detector_name+"-Monitor",detectorName=detector_name))
    except requests.exceptions.HTTPError as err:
        print('failed to create detector: {name}. Error: {err}'.format(name=detector['name'],err=err))

    return
