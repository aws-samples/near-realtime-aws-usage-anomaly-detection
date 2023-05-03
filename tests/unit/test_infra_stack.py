import aws_cdk as core
import aws_cdk.assertions as assertions

from infra.usage_anomaly_detector import UsageAnomalyDetectorStack

# example tests. To run these tests, uncomment this file along with the example
# resource in infra/usage_anomaly_detector.py
def test_sqs_queue_created():
    app = core.App()
    stack = UsageAnomalyDetectorStack(app, "infra")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
