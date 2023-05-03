from boto3 import client
from os import getenv
from datetime import datetime, timedelta

AWS_REGION = getenv('AWS_REGION', 'us-east-1')
ANOMALY_EVAL_MINUTES = getenv('ANOMALY_EVAL_PERIOD', 80)
NOTIF_TOPIC_ARN = getenv('NOTIF_TOPIC_ARN')

ec2_cli = client('ec2', region_name=AWS_REGION)
lambda_cli = client('lambda', region_name=AWS_REGION)
cloudwatch_cli = client('cloudwatch', region_name=AWS_REGION)
sns_cli = client('sns', region_name=AWS_REGION)

time_now = datetime.utcnow()
time_anomly_period = time_now - timedelta(minutes=ANOMALY_EVAL_MINUTES)
time_yesterday = time_anomly_period - timedelta(days=1)

def ec2_usage():
    EC2_RUNNING_STATE = 'running'
    EC2_ALL_COUNT = 0
    EC2_ANOMALY_PERIOD_COUNT = 0

    paginator = ec2_cli.get_paginator('describe_instances')
    response_iterator = paginator.paginate(
        PaginationConfig={
            'PageSize': 100
        }
    )
    instances = []
    for response in response_iterator:
        for instance in response["Reservations"]:
            instance_obj = instance
            instances.append(instance_obj)

    for _instances in instances:
        for instance in _instances['Instances']:
            if instance['State']['Name'] == EC2_RUNNING_STATE:
                EC2_ALL_COUNT += 1
            
            instance_launchtime = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
            launchtime = datetime.strptime(instance_launchtime, '%Y-%m-%d %H:%M:%S')
            if launchtime <= time_now and launchtime > time_anomly_period:
                EC2_ANOMALY_PERIOD_COUNT += 1
                
    print(f'ec2_all_count: {EC2_ALL_COUNT}, ec2_anomaly_period_count:{EC2_ANOMALY_PERIOD_COUNT}')
    return EC2_ALL_COUNT, EC2_ANOMALY_PERIOD_COUNT

def ebs_usage():
    EBS_ALL_COUNT = 0
    EBS_ANOMALY_PERIOD_COUNT = 0
    
    paginator = ec2_cli.get_paginator('describe_volumes')
    response_iterator = paginator.paginate(
        PaginationConfig={
            'PageSize': 100
        }
    )

    for response in response_iterator:
        for volume in response["Volumes"]:
            EBS_ALL_COUNT += 1
            ebs_createdtime = volume['CreateTime'].strftime('%Y-%m-%d %H:%M:%S')
            createdtime = datetime.strptime(ebs_createdtime, '%Y-%m-%d %H:%M:%S')
            if createdtime <= time_now and createdtime > time_anomly_period:
                EBS_ANOMALY_PERIOD_COUNT += 1

    print(f'ebs_all_count: {EBS_ALL_COUNT}, ebs_anomaly_period_count:{EBS_ANOMALY_PERIOD_COUNT}')
    return EBS_ALL_COUNT, EBS_ANOMALY_PERIOD_COUNT

def get_lambda_metrics_stats(function_name, metric_name, start_time, end_time):
    response = cloudwatch_cli.get_metric_statistics(
        Namespace='AWS/Lambda',
        MetricName=metric_name,
                Dimensions=[
                    {
                        'Name': 'FunctionName',
                        'Value': function_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=['Average']
            )
    
    if len(response['Datapoints']) == 0:
        return 0
    return int(response['Datapoints'][0]['Average'])

def lambda_usage():
    LAMBDA_USAGE = []

    paginator = lambda_cli.get_paginator('list_functions')
    response_iterator = paginator.paginate(
        PaginationConfig={
        'PageSize': 100
        }
    )

    for response in response_iterator:
        for _function in response["Functions"]:
            function_detail = {}
            function_name = _function['FunctionName']            
            
            
            function_detail['FunctionName'] = function_name
            function_detail['AnomalyPeriodInvokeCount'] = get_lambda_metrics_stats(function_name, 'Invocations', time_anomly_period, time_now)
            function_detail['24HAvgInvokeCount'] = get_lambda_metrics_stats(function_name, 'Invocations', time_now - timedelta(days=1), time_now)
            
            LAMBDA_USAGE.append(function_detail)
    
    print(LAMBDA_USAGE)
    return LAMBDA_USAGE

def handler(event, context):
    
    notif_message = '\n Please check opensearch dashboard for more details!'
    for record in event["Records"]:
        alert_subject = record["Sns"].get("Subject")
        if alert_subject:
            if "ec2" in alert_subject:
                ec2_all_count, ec2_anomaly_period_count = ec2_usage()
                notif_message = f'\n  - Total Running EC2 Count: {ec2_all_count}\n  - EC2 RunInstances during Anomaly Period: {ec2_anomaly_period_count}' + notif_message
            elif "ebs" in alert_subject:
                ebs_all_count, ebs_anomaly_period_count = ebs_usage()
                notif_message = f'\n  - Total Volume Count: {ebs_all_count}\n  - Volumes Created during Anomaly Period: {ebs_anomaly_period_count}' + notif_message
            elif "lambda" in alert_subject:
                lambda_res = lambda_usage()
                message = '\n Lambda Usage Details(FunctionName, AnomalyPeriodInvokeCount, 24HAvgInvokeCount): \n'
                lambda_details = ''
                for r in lambda_res:
                    function_name = r['FunctionName']
                    anomaly_period_invoke_count = r['AnomalyPeriodInvokeCount']
                    avg_anomaly_invoke_count = r['24HAvgInvokeCount']
                    lambda_details = lambda_details + f'\n - {function_name}\t{anomaly_period_invoke_count}\t{avg_anomaly_invoke_count}'
                notif_message = message + lambda_details + notif_message
            else:
                print('failed to get service specific subject.')

        alert_message = record["Sns"].get("Message") + notif_message

        response = sns_cli.publish(
            TopicArn = NOTIF_TOPIC_ARN,
            Message = alert_message,
            Subject = alert_subject
        )
        print(response)




