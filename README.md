# aws-c7n-wazuh-extension
An extension to integrate aws c7n and wazuh

# Scope
This script assumes the existence of an SQS queue dedicated to aws C7N alerts that Wazuh can fully control. We will be deleting messages once we are done processing them.

# Example C7N Configuration
actions:
    - type: notify
      to: 
        - wazuh
      transport:
        type: sqs
        region: "{sqs_region}"
        queue: "https://sqs.{sqs_region}.amazonaws.com/{account_id}/{queue_name}"
        
# Example Wazuh Configuration
To run this extension, we prefer to run through the generic command wodle. botocore and boto3 are already installed in the embedded python3 environment

<wodle name="command">
    <disabled>no</disabled>
    <tag>aws-c7n</tag>
    <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/aws/aws_c7n.py --sqs_queue_url https://sqs.{sqs_region}.amazonaws.com/{account_id}/{queue_name}</command>
    <interval>30m</interval>
    <ignore_output>yes</ignore_output>
    <run_on_start>no</run_on_start>
    <timeout>21600</timeout>
</wodle>
  
  # Rules
  Tentatively taking up RuleIds:105000
  
  <group name="amazon,aws,c7n,">
    <!-- aws.c7n wodle -->
    <rule id="105000" level="7">
        <decoded_as>json</decoded_as>
        <field name="integration">^aws.c7n$</field>
        <description>c7n alert</description>
    </rule>
</group>
