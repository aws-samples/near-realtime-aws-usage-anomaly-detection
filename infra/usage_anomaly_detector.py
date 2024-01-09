from os import path
from aws_cdk import (
    Aspects,
    Stack, Duration, RemovalPolicy, CfnOutput, CfnJson, CfnParameter, CustomResource, Fn, 
    aws_cloudtrail as cloudtrail,
    aws_s3 as s3,
    aws_logs as logs,
    aws_cognito as cognito,
    aws_opensearchservice as opensearch,
    aws_ec2 as ec2,
    aws_logs_destinations as destinations,
    aws_iam as iam,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subs,
    custom_resources as cr,
    aws_lambda as _lambda,
    aws_kms as kms
)
from cdk_nag import NagSuppressions
from aws_cdk.aws_lambda_event_sources import SnsEventSource
from constructs import Construct

PWD = path.dirname(path.realpath(__file__))
LAMBDA_DIR = path.join(PWD, "..", "lambdas")
SHARED_DIR = path.join(PWD, "..", "shared")

class UsageAnomalyDetectorStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # sns key
        sns_aws_key = kms.Key.from_lookup(self, 'sns-aws-key',
            alias_name='alias/aws/sns'
        )

        # contexts/parameteres
        enable_lambda_trail = self.node.try_get_context('enable-lambda-trail').lower()

        opensearch_version = self.node.try_get_context('opensearch-version')
        opensearch_version_matrix = {
            "OPENSEARCH_1_3": opensearch.EngineVersion.OPENSEARCH_1_3,
            "OPENSEARCH_2_3": opensearch.EngineVersion.OPENSEARCH_2_3,
            "OPENSEARCH_2_5": opensearch.EngineVersion.OPENSEARCH_2_5,
            "OPENSEARCH_2_7": opensearch.EngineVersion.OPENSEARCH_2_7,
            "OPENSEARCH_2_9": opensearch.EngineVersion.OPENSEARCH_2_9
        }

        existing_opensearch_domain_endpoint = self.node.try_get_context('opensearch-domain-endpoint')
        existing_opensearch_access_role_arn = self.node.try_get_context('opensearch-access-role-arn')
        if (existing_opensearch_domain_endpoint == "" and existing_opensearch_access_role_arn != "" ) or \
            (existing_opensearch_domain_endpoint != "" and existing_opensearch_access_role_arn == ""):
            raise ValueError("opensearch-domain-endpoint and opensearch-access-role-arn must be set together")
        
        if existing_opensearch_access_role_arn:
            opensearch_access_role = iam.Role.from_role_arn(
                self,
                'opensearch-access-role',
                existing_opensearch_access_role_arn,
                mutable=False
            )

        # application prefix for naming
        application_prefix = CfnParameter(
            self, 
            'application-prefix',
            type = "String",
            description = "application prefix for naming",
            default = "usage-anomaly-detector",
            allowed_pattern = "^[a-z][a-z0-9-]{2,27}$",
            min_length = 3,
            max_length = 22
        ).value_as_string

        # opensearch alert notification email
        opensearch_alert_email = CfnParameter(
            self, 
            'opensearch-alert-email',
            type = "String",
            description = "Email address for receiving opensearch email alerts",
            default = "example@email.com"
        ).value_as_string

        # cloudtrail trail
        trail_bucket = s3.Bucket(
            self, 
            'usage-anomaly-detector-trail-bucket',
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED, 
            enforce_ssl=True                       
        )
        NagSuppressions.add_resource_suppressions(trail_bucket,[{
            'id': 'AwsSolutions-S1', 'reason': 'trail logs bucket does not need access logging'
        }])

        trail = cloudtrail.Trail(
            self, 
            'usage-anomaly-detector-trail',
            management_events = cloudtrail.ReadWriteType.ALL,
            send_to_cloud_watch_logs = True,
            cloud_watch_logs_retention = logs.RetentionDays.ONE_DAY,
            bucket=trail_bucket,
            enable_file_validation = True,
            is_multi_region_trail = True
        )
         
        # enable lambda logging if explictly set
        if enable_lambda_trail == 'true':
            trail.log_all_lambda_data_events()

        # opensearch alerts - sns role
        opensearch_alerts_sns_role = iam.Role(
            self, 
            'opensearch-alerts-sns-role',
            assumed_by=iam.ServicePrincipal("es.amazonaws.com"),
            description='iam role for opensearch to send alert emails via sns',
        )

        # opensearch email alerts - sns topic
        alert_topic = sns.Topic(
            self, 
            "usage-anomaly-detector-alert-topic",
            display_name = "Usage Anomaly Detector Alert",
            master_key=sns_aws_key
        )

        opensearch_alerts_sns_role.add_to_policy(iam.PolicyStatement(
            actions = ["sns:*"],
            resources = [alert_topic.topic_arn]
        ))

        # opensearch alert notification - sns topic
        notif_topic = sns.Topic(
            self, 
            "usage-anomaly-detector-notif-topic",
            display_name = "Usage Anomaly Detector Notification",
            master_key=sns_aws_key
        )
        notif_topic.add_subscription(sns_subs.EmailSubscription(email_address=opensearch_alert_email))

        # opensearch alert notification function role
        opensearch_alert_notif_fn_role = iam.Role(
            self, 
            'opensearch-alerts-notif-fn-role',
            assumed_by = iam.ServicePrincipal("lambda.amazonaws.com"),
            description='iam role for opensearch alert notification enrichment lambda function',
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")],
            inline_policies={"ResourcePolicy": iam.PolicyDocument(statements = [
                iam.PolicyStatement(actions = ["ec2:Describe*", "lambda:GetFunction*", "lambda:ListFunction*", "cloudwatch:GetMetric*"],resources = ["*"]),
                iam.PolicyStatement(actions = ["sns:*"], resources = [notif_topic.topic_arn])]
            )}
        )

        # opensearch config - function layer
        opensearch_config_function_layer = _lambda.LayerVersion(
            self, 
            'opensearch-config-function-layer',
            code = _lambda.Code.from_asset(path.join(SHARED_DIR)),
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_9]
        )

        # setup opensearch
        OPENSEARCH_DOMAIN_ENDPOINT = existing_opensearch_domain_endpoint
        if not existing_opensearch_domain_endpoint:
            
            # opensearch cognito user/identity pool
            domain_user_pool = cognito.CfnUserPool(
            self, 
            'opensearch-cognito-user-pool',
            admin_create_user_config = cognito.CfnUserPool.AdminCreateUserConfigProperty(
                allow_admin_create_user_only = True
            ),
            username_attributes = ["email"],
            auto_verified_attributes = ["email"],
            policies=cognito.CfnUserPool.PoliciesProperty(
                password_policy=cognito.CfnUserPool.PasswordPolicyProperty(
                    minimum_length=8,
                    require_lowercase=True,
                    require_uppercase=True,
                    require_numbers=True,
                    require_symbols=True
                )
            ),
            user_pool_add_ons=cognito.CfnUserPool.UserPoolAddOnsProperty(
                advanced_security_mode="ENFORCED"
            )
        )

            cognito_domain_suffix = Fn.select(4, Fn.split("-", Fn.select(2, Fn.split("/", self.stack_id))))
            cognito.CfnUserPoolDomain(
            self, 
            'opensearch-cognito-user-pool-domain',
            domain =  f"{application_prefix}-{cognito_domain_suffix}",
            user_pool_id = domain_user_pool.ref
        )

            domain_identity_pool = cognito.CfnIdentityPool(
            self, 
            'opensearch-cognito-identity-pool',
            allow_unauthenticated_identities = False,
            cognito_identity_providers = []  
        )

            # cloudwatch to opensearch - lambda function IAM role
            cloudwatch_to_opensearch_lambda_role = iam.Role(
                self, 
                'cloudwatch-to-opensearch-lambda-role',
                assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                description='iam role for cloudwatch logs to opensearch lambda function',
                managed_policies = [
                    iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
                ]
            )
        
            # opensearch limited role
            opensearch_limited_user_role = iam.Role(
            self, 
            'opensearch-limited-user-role',
            description = 'iam role for opensearch cognito limited user',
            assumed_by = iam.FederatedPrincipal('cognito-identity.amazonaws.com',{
                "StringEquals": { "cognito-identity.amazonaws.com:aud": domain_identity_pool.ref },
                "ForAnyValue:StringLike": { "cognito-identity.amazonaws.com:amr": "authenticated"},
                },
                "sts:AssumeRoleWithWebIdentity"
            ) 
        )

            # opensearch admin role
            opensearch_admin_user_role = iam.Role(
            self, 
            'opensearch-admin-user-role',
            description = 'iam role for opensearch cognito admin user',
            assumed_by = iam.FederatedPrincipal('cognito-identity.amazonaws.com', {
                    "StringEquals": { "cognito-identity.amazonaws.com:aud": domain_identity_pool.ref },
                    "ForAnyValue:StringLike": { "cognito-identity.amazonaws.com:amr": "authenticated"},
                },
                "sts:AssumeRoleWithWebIdentity"
            )
        )

            cognito.CfnUserPoolGroup(
            self, 
            'opensearch-cognito-user-pool-group',
            user_pool_id = domain_user_pool.ref,
            group_name = 'opensearch-admin',
            role_arn = opensearch_admin_user_role.role_arn
        )

        
            # opensearch admin function role
            opensearch_admin_fn_role = iam.Role(
            self, 
            'opensearch-admin-fn-role',
            assumed_by = iam.ServicePrincipal("lambda.amazonaws.com"),
            description = 'iam role for opensearch admin function',
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")]
        )

            opensearch_http_policy = iam.ManagedPolicy(
            self, 
            'opensearch-http-policy',
            description = 'iam policy to allow opensearch http methods',
            roles = [opensearch_admin_user_role, opensearch_admin_fn_role, cloudwatch_to_opensearch_lambda_role]
        )

                
            # opensearch role
            opensearch_role = iam.Role(
            self, 
            'opensearch-role',
            description = 'opensearch iam role',
            assumed_by = iam.ServicePrincipal("es.amazonaws.com"),
            managed_policies = [iam.ManagedPolicy.from_aws_managed_policy_name("AmazonOpenSearchServiceCognitoAccess")]
        )

            # opensearch
            domain_arn = f"arn:aws:es:{self.region}:{self.account}:domain/{application_prefix}/*"

            opensearch_http_policy.add_statements(iam.PolicyStatement(
            actions = ['es:ESHttpPost', 'es:ESHttpGet', 'es:ESHttpPut', 'es:ESHttpPatch'],
            effect = iam.Effect.ALLOW,
            resources = [domain_arn] 
        ))
        
            domain = opensearch.Domain(
            self, 
            'usage-anomaly-detector-os',
            version = opensearch_version_matrix[opensearch_version],
            removal_policy = RemovalPolicy.DESTROY,

            capacity = opensearch.CapacityConfig(
                data_node_instance_type = 'm6g.large.search',
                data_nodes = 3),

            ebs = opensearch.EbsOptions(
                enabled = True,
                volume_size = 100,
                volume_type = ec2.EbsDeviceVolumeType.GP3),

            enforce_https = True,
            node_to_node_encryption = True,
            encryption_at_rest = opensearch.EncryptionAtRestOptions(
                enabled = True),
            use_unsigned_basic_auth = True,

            fine_grained_access_control = opensearch.AdvancedSecurityOptions(
                master_user_arn = opensearch_admin_fn_role.role_arn
            ),

            cognito_dashboards_auth = opensearch.CognitoOptions(
                role = opensearch_role,
                user_pool_id = domain_user_pool.ref,
                identity_pool_id = domain_identity_pool.ref),

            access_policies = [iam.PolicyStatement(
                actions = ["es:ESHttp*"],
                effect = iam.Effect.ALLOW,
                principals = [iam.AnyPrincipal()],
                resources = [domain_arn]
            )],

            zone_awareness=opensearch.ZoneAwarenessConfig(availability_zone_count=3)
        )

            OPENSEARCH_DOMAIN_ENDPOINT = domain.domain_endpoint

            domain_user_pool_clients = cr.AwsCustomResource(
            self, 
            'opensearch-cognito-client-id-resource',
            policy = cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources = [domain_user_pool.attr_arn]),
            on_create = cr.AwsSdkCall(
                service = 'CognitoIdentityServiceProvider',
                action = 'listUserPoolClients',
                parameters = {"UserPoolId":domain_user_pool.ref},
                physical_resource_id = cr.PhysicalResourceId.of('ClientId-'+application_prefix)
            )
        )
            domain_user_pool_clients.node.add_dependency(domain)
        
            client_id = domain_user_pool_clients.get_response_field('UserPoolClients.0.ClientId')
            provider_name = f"cognito-idp.{self.region}.amazonaws.com/{domain_user_pool.ref}:{client_id}"
            cognito.CfnIdentityPoolRoleAttachment(self, 'domain-user-pool-role-attachment',
                identity_pool_id = domain_identity_pool.ref,
                roles = {
                    'authenticated': opensearch_limited_user_role.role_arn
                },
                role_mappings = CfnJson(self, 'role-mappings-json',
                    value={
                        provider_name:{
                            'Type': 'Token',
                            'AmbiguousRoleResolution': 'AuthenticatedRole'
                        }
                    }
                )
            )

            # opensearch config - function trigger
            opensearch_config_function = _lambda.Function(
            self, 
            'opensearch-config-function',
            description = 'opensearch user/role config automation lambda function trigger',
            code = _lambda.Code.from_asset(path.join(LAMBDA_DIR, "OpensearchConfig")),
            handler = "main.handler",
            runtime = _lambda.Runtime.PYTHON_3_9,
            timeout = Duration.seconds(120),
            layers = [opensearch_config_function_layer],
            role = opensearch_admin_fn_role,
            environment = {
                "OPENSEARCH_HOST": OPENSEARCH_DOMAIN_ENDPOINT
            }
        )

            opensearch_config_fn_provider = cr.Provider(
            self, 
            'opensearch-config-fn-provider',
            on_event_handler = opensearch_config_function,
            log_retention=logs.RetentionDays.ONE_DAY
        )
       
            opensearch_config_cr = CustomResource(
            self, 
            'opensearch-config',
            service_token = opensearch_config_fn_provider.service_token,
            properties={
                "api_requests": [
                    {
                        "method": "patch",
                        "path": "/_plugins/_security/api/rolesmapping/security_manager",
                        "body": [{
                            "op": "add", 
                            "path": "/backend_roles", 
                            "value": [
                                opensearch_admin_fn_role.role_arn,
                                opensearch_admin_user_role.role_arn
                            ]  
                        }]
                    },
                    {
                        "method": "patch",
                        "path": "/_plugins/_security/api/rolesmapping/all_access",
                        "body":[{
                            "op":"add",
                            "path":"/backend_roles",
                            "value":[
                                opensearch_admin_fn_role.role_arn,
                                opensearch_admin_user_role.role_arn,
                                opensearch_limited_user_role.role_arn,
                                cloudwatch_to_opensearch_lambda_role.role_arn
                            ]
                        }]
                    }
                ]
            }
        )
            
            # opensearch domain endpoint
            CfnOutput(
                self, 
                'Opensearch dashboard endpoint',
                value = 'https://' + domain.domain_endpoint + '/_dashboards',
                description = 'opensearch dashboard endpoint'
            )

            # cognito user pool - opensearch user create url
            CfnOutput(
                self, 
                'Opensearch create user url',
                value = 'https://' + self.region + ".console.aws.amazon.com/cognito/users?region=" + self.region +  "#/pool/" + domain_user_pool.ref + "/users",
                description = 'cognito console url for creating opensearch user'
            )
            
        # cloudwatch to opensearch - lambda function
        cloudwatch_to_opensearch_lambda_function = _lambda.Function(
            self, 
            'cloudwatch-to-opensearch-lambda-function',
            description = 'cloudwatch logs to opensearch lambda function',
            code = _lambda.Code.from_asset(path.join(LAMBDA_DIR, "LogsToElasticSearch")),
            handler = "index.handler",
            runtime = _lambda.Runtime.NODEJS_18_X,
            timeout = Duration.seconds(120),
            role = opensearch_access_role if existing_opensearch_access_role_arn else cloudwatch_to_opensearch_lambda_role,
            environment = {
                "OPENSEARCH_DOMAIN_ENDPOINT": OPENSEARCH_DOMAIN_ENDPOINT,
                "OPENSEARCH_VERSION": opensearch_version
            }
        )

        # cloudwatch log group - opensearch subs filter
        cloudwatch_log_subscription = logs.SubscriptionFilter(
            self, 
            'usage-anomaly-detector-logs-subs-filter',
            log_group = trail.log_group,
            destination = destinations.LambdaDestination(cloudwatch_to_opensearch_lambda_function),
            filter_pattern = logs.FilterPattern.all_events()
        )
        permission = cloudwatch_log_subscription.node.try_find_child("CanInvokeLambda")
        if permission is not None:
            cloudwatch_log_subscription.node.add_dependency(permission)
        
        # opensearch anomaly detector - lambda function
        opensearch_anomalydetector_function = _lambda.Function(
            self, 
            'opensearch-anomalydetector-function',
            description = 'opensearch anomaly detector config automation lambda function',
            code = _lambda.Code.from_asset(path.join(LAMBDA_DIR, "OpensearchAnomalyDetector")),
            handler = "main.handler",
            runtime = _lambda.Runtime.PYTHON_3_9,
            timeout = Duration.seconds(600),
            layers = [opensearch_config_function_layer],
            role = opensearch_access_role if existing_opensearch_access_role_arn else opensearch_admin_fn_role,
            environment = {
                "OPENSEARCH_HOST": OPENSEARCH_DOMAIN_ENDPOINT,
                "OPENSEARCH_VERSION": opensearch_version,
                "ENABLE_LAMBDA_TRAIL": enable_lambda_trail,
                "SNS_TOPIC_ARN": alert_topic.topic_arn,
                "SNS_ALERT_ROLE": opensearch_alerts_sns_role.role_arn
            }
        )

        opensearch_anomalydetector_fn_provider = cr.Provider(
            self, 
            'opensearch-anomalydetector-fn-provider',
            on_event_handler = opensearch_anomalydetector_function,
            log_retention=logs.RetentionDays.ONE_DAY
        )

        opensearch_anomalydetector_cr = CustomResource(
            self, 
            'opensaerch-anomalydetector',
            service_token = opensearch_anomalydetector_fn_provider.service_token
        )
        if not existing_opensearch_access_role_arn:
            opensearch_anomalydetector_cr.node.add_dependency(opensearch_config_cr)
        else:
            opensearch_anomalydetector_cr.node.add_dependency(cloudwatch_log_subscription)

        opensearch_anomalydetector_notif_function = _lambda.Function(
            self, 
            'opensearch-anomalydetector-notif-function',
            description = 'opensearch anomaly detector notification enrichment lambda function',
            code = _lambda.Code.from_asset(path.join(LAMBDA_DIR, "OpensearchAnomalyDetectorNotif")),
            handler = "main.handler",
            runtime = _lambda.Runtime.PYTHON_3_9,
            timeout = Duration.seconds(600),
            role = opensearch_alert_notif_fn_role,
            environment = {
                "ANOMALY_EVAL_MINUTES": '80',
                "NOTIF_TOPIC_ARN": notif_topic.topic_arn
            }
        )
        opensearch_anomalydetector_notif_function.add_event_source(SnsEventSource(alert_topic,filter_policy={}))
