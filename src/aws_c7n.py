#!/var/ossec/framework/python/bin/python3

# /var/ossec/framework/python/bin/python3 /var/ossec/wodles/aws/aws_c7n.py --sqs_queue_url https://sqs.{sqs_region}.amazonaws.com/{sqs_account_id}/{sqs_queue_name}
# Copyright: GPLv3
# Jamie Orlando <orlando.jamie@gmail.com>

__author__ = "Jamie Orlando"
__copyright__ = "GPLv3"

import sys
import argparse
import signal
import json
import socket
import boto3
import botocore
import os
import zlib
import re
import base64

# Constants
###############################################################################
RECEIVE_MESSAGE_BATCH_SIZE = 10
DEBUG_LEVEL = 0
SQS_QUEUE_REGEX = r"^https://sqs\.(?P<region>[^\s]+?)\.amazonaws\.com/(?P<account_id>\d{12}?)/(?P<queue_name>[^\s]+?)$"


# Classes
###############################################################################

class C7nSqsQueue:
  """
    Class with common methods
    :param access_key: AWS access key id
    :param secret_key: AWS secret access key
    :param aws_profile: AWS profile
    :param iam_role_arn: IAM Role
    :param sqs_queue_url: Sqs queue url to retrieve messages from
  """
  def __init__(self, sqs_queue_url, access_key=None, secret_key=None, profile=None, iam_role_arn=None):
    self.sqs_queue_url = sqs_queue_url
    self.access_key = access_key
    self.secret_key = secret_key
    self.profile = profile
    self.iam_role_arn = iam_role_arn
    # Next bit adds self.sqs_region, self.sqs_queue_name, self.sqs_queue_account_id
    self.parse_sqs_queue_url()
    # get path and version from ossec.init.conf
    with open('/etc/ossec-init.conf') as f:
      lines = f.readlines()
      re_ossec_init = re.compile(r'^([A-Z]+)={1}"{1}([\w\/.]+)"{1}$')
      self.wazuh_path = re.search(re_ossec_init, lines[0]).group(2)
      self.wazuh_version = re.search(re_ossec_init, lines[2]).group(2)
    self.wazuh_queue = '{0}/queue/ossec/queue'.format(self.wazuh_path)
    self.wazuh_wodle = '{0}/wodles/aws'.format(self.wazuh_path)
    # Information on formulating a Wazuh header
    # https://documentation.wazuh.com/current/development/message-format.html
    self.msg_header = "1:Wazuh-AWS-c7n:"
    return

  def parse_sqs_queue_url(self):
    try:
      match = re.match(SQS_QUEUE_REGEX, self.sqs_queue_url)
      self.sqs_region = match.group('region')
      self.sqs_queue_name = match.group('queue_name')
      self.sqs_queue_account_id = match.group('account_id')
    except:
      raise ValueError("could not parse sqs_queue_url: {0}".format(self.sqs_queue_url))
    return

  def send_msg(self, msg):
    """
    Sends an AWS event to the Wazuh Queue
    :param msg: JSON message to be sent.
    :param wazuh_queue: Wazuh queue path.
    :param msg_header: Msg header.
    """
    try:
      json_msg = json.dumps(msg, default=str)
      debug(json_msg, 3)
      s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
      s.connect(self.wazuh_queue)
      s.send("{header}{msg}".format(header=self.msg_header,
                                    msg=json_msg).encode())
      s.close()
    except socket.error as e:
      if e.errno == 111:
        print("ERROR: Wazuh must be running.")
        sys.exit(11)
      elif e.errno == 90:
        print("ERROR: Message too long to send to Wazuh.  Skipping message...")
        debug(
          '+++ ERROR: Message longer than buffer socket for Wazuh.  Consider increasing rmem_max  Skipping message...',
          1)
      else:
        print("ERROR: Error sending message to wazuh: {}".format(e))
        sys.exit(13)
    except Exception as e:
      print("ERROR: Error sending message to wazuh: {}".format(e))
      sys.exit(13)
  
  def get_client(self, service_name=None, region=None):
    conn_args = {}

    if self.access_key is not None and self.secret_key is not None:
      conn_args['aws_access_key_id'] = self.access_key
      conn_args['aws_secret_access_key'] = self.secret_key

    if self.profile is not None:
      conn_args['profile_name'] = self.profile

    # only for Inspector
    if region is not None:
      conn_args['region_name'] = region

    boto_session = boto3.Session(**conn_args)

    # If using a role, create session using that
    try:
      if self.iam_role_arn:
        sts_client = boto_session.client('sts')
        sts_role_assumption = sts_client.assume_role(RoleArn=self.iam_role_arn,
                                                      RoleSessionName='WazuhLogParsing')
        sts_session = boto3.Session(aws_access_key_id=sts_role_assumption['Credentials']['AccessKeyId'],
                                    aws_secret_access_key=sts_role_assumption['Credentials']['SecretAccessKey'],
                                    aws_session_token=sts_role_assumption['Credentials']['SessionToken'])
        client = sts_session.client(service_name=service_name)
      else:
        client = boto_session.client(service_name=service_name)
    except botocore.exceptions.ClientError as e:
      print("ERROR: Access error: {}".format(e))
      sys.exit(3)
    return client

  def iter_queue(self):
    debug("+++ Working on SQS queue: {0}".format(self.sqs_queue_url), 1)
    sqs_client = self.get_client(service_name='sqs', region=self.sqs_region)
    unread_messages = True
    while unread_messages:
      sqs_response = sqs_client.receive_message(QueueUrl=self.sqs_queue_url,
                            MaxNumberOfMessages=RECEIVE_MESSAGE_BATCH_SIZE)
      sqs_messages = sqs_response.get("Messages",[])
      unread_messages = True if len(sqs_messages) > 0 else False
      for sqs_message in sqs_messages:
        b64_encoded_message_body = sqs_message['Body']
        compressed_message_body = base64.b64decode(b64_encoded_message_body)
        message_body_text = zlib.decompress(compressed_message_body)
        receipt_handle = sqs_message.get('ReceiptHandle', None)
        try:
          message_body = json.loads(message_body_text)
          # If we want to search for "wazuh" in to: field, use the following
          # if "wazuh" in message_body.get('action', {}).get('to', []):
          # Right now, we are assuming the whole queue is for wazuh to process
        except Exception as e:
          print(e)
          pass
        # Now process message into wazuh
        keylist = [key for key in message_body.keys()]
        keylist.remove("resources")
        for resource in message_body.get("resources", []):
          wazuh_message = {
            "integration": "aws.c7n",
            "msg": "c7n Result",
            "matched_resource": resource,
          }
          for key in keylist:
            wazuh_message[key] = message_body[key]
          self.send_msg(wazuh_message)
          # if successfull, delete message
          if receipt_handle is not None:
            self.delete_processed_message(sqs_client, receipt_handle)
    return

  def delete_processed_message(self, sqs_client, receipt_handle):
    delete_message_args = {"QueueUrl": self.sqs_queue_url, "ReceiptHandle": receipt_handle}
    sqs_client.delete_message(**delete_message_args)
    return


# Functions
###############################################################################
def debug(msg, msg_level):
  if DEBUG_LEVEL >= msg_level:
    print('DEBUG: {debug_msg}'.format(debug_msg=msg))
  return

def arg_sqs_queue_url(arg_string):
  if not re.match(SQS_QUEUE_REGEX, arg_string):
    raise ValueError("Not a valid sqs url: {0}".format(arg_string))
  return arg_string

def get_script_arguments():
  parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                    description="Wazuh wodle for monitoring AWS",
                                    formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debug')
  parser.add_argument('-a', '--access_key', dest='access_key', help='S3 Access key credential', default=None)
  parser.add_argument('-k', '--secret_key', dest='secret_key', help='S3 Secret key credential', default=None)
  parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                      default=None)
  parser.add_argument('-i', '--iam_role_arn', dest='iam_role_arn',
                      help='ARN of IAM role to assume for access to S3 bucket',
                      default=None)
  parser.add_argument('-q', '--sqs_queue_url', dest='sqs_queue_url',
                      help='sqs_queue_url for c7n queue', type=arg_sqs_queue_url, default=None)
  return parser.parse_args()

def _signal_handler(signal, frame):
  print("ERROR: SIGINT received.")
  sys.exit(3)


# Main
###############################################################################
def main(argv):
  # Parse arguments
  options = get_script_arguments()

  if int(options.debug) > 0:
    global DEBUG_LEVEL
    DEBUG_LEVEL = int(options.debug)
    debug('+++ Debug mode on - Level: {debug}'.format(debug=options.debug), 1)

  try:
    c7n_queue = C7nSqsQueue(sqs_queue_url=options.sqs_queue_url, access_key=options.access_key, secret_key=options.secret_key, profile=options.aws_profile, iam_role_arn=options.iam_role_arn)
    c7n_queue.iter_queue()

  except Exception as err:
    debug("+++ Error: {}".format(err), 2)
    if DEBUG_LEVEL > 0:
      raise
    print("ERROR: {}".format(err))
  return


if __name__ == '__main__':
  try:
    debug('Args: {args}'.format(args=str(sys.argv)), 2)
    signal.signal(signal.SIGINT, _signal_handler)
    main(sys.argv[1:])
    sys.exit(0)
  except Exception as e:
    print("Unknown error: {}".format(e))
    if DEBUG_LEVEL > 0:
      raise
    sys.exit(1)

