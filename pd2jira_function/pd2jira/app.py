import os
import logging
import urllib
import json
import boto3
import datetime
from jira import JIRA

logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', logging.DEBUG))
logging.getLogger('boto3').setLevel(
    os.environ.get('BOTO_LOG_LEVEL', logging.ERROR))
logging.getLogger('jira').setLevel(
    os.environ.get('JIRA_LOG_LEVEL', logging.ERROR))

STAGE = os.getenv('STAGE', 'dev')

# connect to SSM to get config
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

DYNAMODB_ENDPOINT = os.environ["DYNAMODB_ENDPOINT"]
DYNAMODB_REGION = os.environ["DYNAMODB_REGION"]
DYNAMODB_TABLE = os.environ["DYNAMODB_TABLE"]

# establish connection to jira
options = {"server": JIRA_URL}

oauth_dict = {
    'access_token': OAUTH_ACCESS_TOKEN,
    'access_token_secret': OAUTH_ACCESS_TOKEN_SECRET,
    'consumer_key': 'pagerduty-to-jira',
    'key_cert': OAUTH_KEY_CERTIFICATE
}

jira = JIRA(options, oauth=oauth_dict)
logger.info("Connected to Jira: {}".format(jira.server_info()))

# establish connection to dynamo
dynamodb = boto3.resource(
    'dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_ENDPOINT)
table = dynamodb.Table(DYNAMODB_TABLE)


def trigger(pd_event):

    # Create a jira
    issue_fields = {
        'project': JIRA_PROJECT,
        'summary': 'Alert - {}'.format(pd_event['incident']['title']),
        'description': pd_event['incident']['description'],
        'issuetype': {'name': ISSUE_TYPE}
    }

    issue = jira.create_issue(fields=issue_fields)
    comment = jira.add_comment(
        issue.key, 'Alert triggered by PagerDutyToJira integration')

    link_fields = {
        'url': pd_event['incident']['html_url'],
        'title': 'PagerDuty Incident'
    }
    jira.add_simple_link(issue.key, link_fields)

    table.put_item(
        Item={
            'incidentid': pd_event['incident']['id'],
            'issuekey': issue.key
        }
    )

    return respond(200, "OK")


def unsupported(pd_event):
    logger.error(
        "Received unsupported event type: {}".format(pd_event['event']))
    return respond(402, "Unsupported Event Type")


def annotate(pd_event):
    try:
        issuekey = get_issue_by_incident(pd_event['incident']['id'])

    except boto3.ClientError as e:
        logger.error(e.response['Error']['Message'])
        return respond(503, e.response['Error']['Message'])

    if issuekey is None:
        logger.warn("Incident mapping not found for {}".format(
            pd_event['incident']['id']))
        return respond(404, "Not Found")

    comment = """
%s

Note: %s
    """ % (pd_event['log_entries'][0]['summary'], pd_event['log_entries'][0]['channel']['content'])
    
    comment_on_issue(issuekey, comment)


def state_change(state_change, pd_event):
    try:
        issuekey = get_issue_by_incident(pd_event['incident']['id'])

    except boto3.ClientError as e:
        logger.error(e.response['Error']['Message'])
        return respond(503, e.response['Error']['Message'])

    if issuekey is None:
        logger.warn("Incident mapping not found for {}".format(
            pd_event['incident']['id']))
        return respond(404, "Not Found")

    comment_on_issue(
        issuekey, pd_event['log_entries'][0]['summary'])


def get_issue_by_incident(incidentid):

    # Pull an issue mapping from dynamo
    response = table.get_item(
        Key={
            'incidentid': incidentid
        }
    )

    try:
        item = response['Item']
        logger.debug("Incident mapping found: {}".format(json.dumps(item)))
        return item['issuekey']
    except KeyError:
        pass


def comment_on_issue(issuekey, comment):
    # Attempt to update issue with a comment.
    issue = jira.issue(issuekey)
    jira.add_comment(
        issue.key, comment)


def lambda_handler(event, context):

    logger.info("PagerDuty event received: {}".format(
        event['detail']['event']))
    logger.debug("Event payload: {}".format(event))

    switcher = {
        'incident.acknowledge': lambda: state_change('acknowledge', event['detail']),
        'incident.annotate': lambda: annotate(event['detail']),
        'incident.assign': lambda: state_change('assign', event['detail']),
        'incident.escalate': lambda: state_change('escalate', event['detail']),
        'incident.resolve': lambda: state_change('resolve', event['detail']),
        'incident.trigger': lambda: trigger(event['detail']),
        'incident.unacknowledge': lambda: state_change('uncknowledge', event['detail'])
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
