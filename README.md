# aws-c7n-wazuh-extension
An extension to integrate aws c7n and wazuh

# Usage
``` bash
usage: usage: tl_aws_c7n.py [options]

Wazuh wodle for monitoring AWS

optional arguments:
  -h, --help            show this help message and exit
  -d DEBUG, --debug DEBUG
                        Enable debug
  -a ACCESS_KEY, --access_key ACCESS_KEY
                        S3 Access key credential
  -k SECRET_KEY, --secret_key SECRET_KEY
                        S3 Secret key credential
  -p AWS_PROFILE, --aws_profile AWS_PROFILE
                        The name of credential profile to use
  -i IAM_ROLE_ARN, --iam_role_arn IAM_ROLE_ARN
                        ARN of IAM role to assume for access to S3 bucket
  -n AWS_ACCOUNT_ALIAS, --aws_account_alias AWS_ACCOUNT_ALIAS
                        AWS Account ID Alias
  -q SQS_QUEUE_URL, --sqs_queue_url SQS_QUEUE_URL
                        sqs_queue_url for c7n queue
```

# Installation
Download the repo and move the src script into the aws wodle directory.
```bash
git clone https://github.com/orlando-jamie/aws-c7n-wazuh-extension.git
cp aws-c7n-wazuh-extension/src/aws_c7n.py /var/ossec/wodles/aws/
chown root:ossec /var/ossec/wodles/aws/aws_c7n.py
chmod 0750 /var/ossec/wodles/aws/aws_c7n.py
```

# Scope
This script assumes the existence of an SQS queue dedicated to aws C7N alerts that Wazuh can fully control. We will be deleting messages once we are done processing them.

# Example C7N Configuration
```yml
actions:
    - type: notify
      to: 
        - wazuh
      transport:
        type: sqs
        region: "{sqs_region}"
        queue: "https://sqs.{sqs_region}.amazonaws.com/{account_id}/{queue_name}"
```

# Example Wazuh Configuration
To run this extension, we prefer to run through the generic command wodle. botocore and boto3 are already installed in the embedded python3 environment

```xml
<wodle name="command">
    <disabled>no</disabled>
    <tag>aws-c7n</tag>
    <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/aws/aws_c7n.py --sqs_queue_url https://sqs.{sqs_region}.amazonaws.com/{account_id}/{queue_name}</command>
    <interval>30m</interval>
    <ignore_output>yes</ignore_output>
    <run_on_start>no</run_on_start>
    <timeout>21600</timeout>
</wodle>
```
  
# Rules
Tentatively taking up RuleIds:105000

```xml
<group name="amazon,aws,c7n,">
    <!-- aws.c7n wodle -->
    <rule id="105000" level="7">
        <decoded_as>json</decoded_as>
        <field name="integration">^aws.c7n$</field>
        <description>c7n alert</description>
    </rule>
</group>
```
