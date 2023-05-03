#!/usr/bin/env python3
import aws_cdk as cdk
from os import getenv
from infra.usage_anomaly_detector import UsageAnomalyDetectorStack
from cdk_nag import AwsSolutionsChecks, NagSuppressions, NagPackSuppression

app = cdk.App()
usage_anomaly_detector_infra_stack = UsageAnomalyDetectorStack(app, app.node.try_get_context('stack-name'),
    env=cdk.Environment(
        region=getenv('AWS_REGION', getenv('CDK_DEFAULT_REGION')), 
        account=getenv('AWS_ACCOUNT_ID', getenv('CDK_DEFAULT_ACCOUNT'))
    ),
    description="Usage Anomaly Detector Stack uksb-1tupbocl1"
)

tags={
   'SolutionName': 'Usage Anomaly Detector',
   'SolutionVersion': 'v1.0.0',
   'SolutionIaC': 'CDK v2'
}

for key, val in tags.items():
    cdk.Tags.of(usage_anomaly_detector_infra_stack).add(key,val)

# nag suppressions
nagsuppression_checks = [
    {
        "rule":"AwsSolutions-L1",
        "reason":"Already using latest version pythnb3.9 & nodejs18.x for lambda"
    },
    {
        "rule":"AwsSolutions-IAM4",
        "reason": "use AWS managed policies for IAM roles for lambda & other cdk defaults"
    },
    {
        "rule":"AwsSolutions-IAM5",
        "reason":"use AWS managed policies from cdk defaults"
    },
    {
        "rule" : "AwsSolutions-OS1",
        "reason" : "using public opensearch domain for solution"
    },
    {
        "rule" : "AwsSolutions-OS3",
        "reason" : "using public opensearch domain for solution, IP restriction can be added by oss user."
    },
    {
        "rule" : "AwsSolutions-OS4",
        "reason" : "does not need dedicated master"
    },
    {
        "rule": "AwsSolutions-OS5",
        "reason": "using cognito for public opensearch dashboard auth"
    },
    {
        "rule": "AwsSolutions-OS9",
        "reason": "solution dedicated opensearch, exempting slow logs/index publish"
    }

]
for checks in nagsuppression_checks:
    NagSuppressions.add_stack_suppressions(usage_anomaly_detector_infra_stack, [
    NagPackSuppression(
        id=checks['rule'],
        reason=checks['reason']
    )
])
    
# nag checks
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
app.synth()
