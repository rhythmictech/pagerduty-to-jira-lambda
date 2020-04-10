import os
import logging
import urllib
import json
import boto3
from jira import JIRA

logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', logging.DEBUG))
logging.getLogger('boto').setLevel(
    os.environ.get('BOTO_LOG_LEVEL', logging.ERROR))
logging.getLogger('boto3').setLevel(
    os.environ.get('BOTO_LOG_LEVEL', logging.ERROR))

STAGE = os.getenv('STAGE', 'dev')

ssm_param_path = os.getenv('AWS_PARAMSTORE_PATH',
                           '/pagerduty-to-jira/{}'.format(STAGE))
client = boto3.client('ssm')
response = client.get_parameters_by_path(
    Path=ssm_param_path, WithDecryption=True)
for param in response['Parameters']:
    env_name = os.path.basename(param['Name'])
    os.environ[env_name] = param['Value']

JIRA_URL = os.environ["JIRA_URL"]
JIRA_PROJECT = os.environ["JIRA_PROJECT"]
ISSUE_TYPE = os.environ["ISSUE_TYPE"]
OAUTH_ACCESS_TOKEN = os.environ["OAUTH_ACCESS_TOKEN"]
OAUTH_ACCESS_TOKEN_SECRET = os.environ["OAUTH_ACCESS_TOKEN_SECRET"]
OAUTH_KEY_CERTIFICATE = os.environ["OAUTH_KEY_CERTIFICATE"]

options = {"server": JIRA_URL}

oauth_dict = {
    'access_token': OAUTH_ACCESS_TOKEN,
    'access_token_secret': OAUTH_ACCESS_TOKEN_SECRET,
    'consumer_key': 'pagerduty-to-jira',
    'key_cert': OAUTH_KEY_CERTIFICATE
}

jira = JIRA(options, oauth=oauth_dict)
logger.info("Connected to Jira: {}".format(jira.server_info()))


def trigger(pd_event):

    # Create a jira
    issue_fields = {
        'project' = JIRA_PROJECT,
        'summary' = 'Alert - {}'.format(pd_event['incident']['title']),
        'description' = pd_event['incident']['description'],
        'issuetype' = {'name': ISSUE_TYPE})

    }

    issue = jira.create_issue(fields=issue_fields)
    comment = jira.add_comment(issue.key, 'Alert triggered by PagerDutyToJira integration')
    jira.add_simple_link(issue.key, pd_event['incident']['html_url'])

    # record issue id in dynamodb for future lookup
    return respond(200, "OK")


def acknowledge(pd_event):
    return respond(200, "OK")


def unsupported(pd_event):
    logger.error(
        "Received unsupported event type: {}".format(pd_event['event']))
    return respond(402, "Unsupported Event Type")


def lambda_handler(event, context):

    logger.info("PagerDuty event received: {}".format(
        event['detail']['event']))
    logger.debug("Event payload: {}".format(event))

    switcher={
        'incident.trigger': lambda: trigger(event['detail']),
        'incident.acknowledge': lambda: acknowledge(event['detail'])
    }

    func = switcher.get(event['detail']['event'],
                        lambda: unsupported(event['detail']))
    return func()


def respond(statusCode, body):
    logger.debug("Status Code: {}".format(statusCode))
    return {
        'statusCode': statusCode,
        'body': body
    }
