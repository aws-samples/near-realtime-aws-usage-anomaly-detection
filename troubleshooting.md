## Troubleshooting

### Missing Anomaly Detector
1. If you do not find any of the detector (_lambda-invoke_, _ebs-create\_volume_, _ec2-run\_instances_) check the cloudwatch logs for the opensearch anomaly detector config automation lambda function. 
2. You can manually re-run the lambda function in case the detector creation fails for some reason.  

### No Data in EC2/EBS/Lambda Opensearch dashboards
1. Check the time window as there might be no events for the specific time window.
2. Generate custom data by triggering the events. You can do so by creating an ec2 instance or ebs volume or just invoking lambda functions.