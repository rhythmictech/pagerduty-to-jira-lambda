import os
import logging
import urllib
import json
import boto3
import datetime
import pdpyras
from jira import JIRA
from jira.resources import User

logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', logging.DEBUG))

for handler in logger.handlers:
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s](%(name)s) %(message)s'))

for lib_logger in ['botocore', 'boto3', 'jira', 'requests_oauthlib', 'oauthlib', 'urllib3']:
    logging.getLogger(lib_logger).setLevel(
        os.environ.get('LIBRARY_LOG_LEVEL', logging.ERROR))

STAGE = os.getenv('STAGE', 'dev')

# connect to SSM to get config
ssm_param_path = os.getenv('AWS_PARAMSTORE_PATH',
                           '/pagerduty-to-jira/{}'.format(STAGE))

ssm = boto3.client('ssm')

paginator = ssm.get_paginator('get_parameters_by_path')
for page in paginator.paginate(Path=ssm_param_path, WithDecryption=True):
    for param in page['Parameters']:
        logger.debug("Setting parameter: {}".format(param['Name']))
        env_name = os.path.basename(param['Name'])
        os.environ[env_name] = param['Value']

JIRA_URL = os.environ["JIRA_URL"]
OAUTH_ACCESS_TOKEN = os.environ["OAUTH_ACCESS_TOKEN"]
OAUTH_ACCESS_TOKEN_SECRET = os.environ["OAUTH_ACCESS_TOKEN_SECRET"]
OAUTH_KEY_CERTIFICATE = os.environ["OAUTH_KEY_CERTIFICATE"]
JIRA_STATUS_ACKNOWLEDGED = os.environ["JIRA_STATUS_ACKNOWLEDGED"]
JIRA_STATUS_RESOLVED = os.environ["JIRA_STATUS_RESOLVED"]

# Dynamo related vars
DYNAMODB_ENDPOINT = os.environ["DYNAMODB_ENDPOINT"]
DYNAMODB_REGION = os.environ["DYNAMODB_REGION"]
DYNAMODB_ISSUE_TABLE = os.environ["DYNAMODB_ISSUE_TABLE"]
DYNAMODB_USER_TABLE = os.environ["DYNAMODB_USER_TABLE"]

# PD related vars
PD_API_KEY = os.environ["PD_API_KEY"]
PD_EVENT_KEY = os.environ["PD_EVENT_KEY"]

# establish connection to jira
options = {"server": JIRA_URL}

oauth_dict = {
    'access_token': OAUTH_ACCESS_TOKEN,
    'access_token_secret': OAUTH_ACCESS_TOKEN_SECRET,
    'consumer_key': 'jira-to-pagerduty-imperva',
    'key_cert': OAUTH_KEY_CERTIFICATE
}

jira = JIRA(options, oauth=oauth_dict)
logger.info("Connected to Jira: {}".format(jira.server_info()))

# establish connection to dynamo
dynamodb = boto3.resource(
    'dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_ENDPOINT)
issue_table = dynamodb.Table(DYNAMODB_ISSUE_TABLE)
user_table = dynamodb.Table(DYNAMODB_USER_TABLE)

# configure pdpyras
pd_session = pdpyras.APISession(PD_API_KEY)


def get_incident_by_issue(issue_id):
    """Query DynamoDB to find linked PagerDuty incident.

    Returns `None` if a linked incident cannot be found.

    Parameters
    ----------
    issue_id : str
        PagerDuty Incident ID
    """

    response = issue_table.get_item(Key={'issuekey': issue_id})

    try:
        item = response['Item']
        logger.debug("Incident mapping found: {}".format(json.dumps(item)))
        return item['incidentid']
    except KeyError:
        return None


def map_jira_user(email):
    """Query DynamoDB to find a PD user mapping. If not found, the original address is returned.

    Parameters
    ----------
    email : str
        Email address of user
    """

    response = user_table.get_item(Key={'jira_email': email})

    try:
        item = response['Item']
        logger.debug("User mapping found: {}".format(json.dumps(item)))
        return item['pd_email']
    except KeyError:
        return email


def lambda_handler(event, context):
    """Lambda entry point.

    Parameters
    ----------
    event : dict
    context : dict
    """

    logger.debug("Jira event received: {}".format(event))

    if event['webhookEvent'] == 'jira:issue_assigned':

        issue_key = event['issue']['key']
        logger.info("Processing issue: {}".format(issue_key))

        incident_id = get_incident_by_issue(issue_key)
        assignee_account_id = event['issue']['fields']['assignee']['accountId']

        # look up user email address
        logger.debug(
            "Attempting to find user for accountId {}".format(assignee_account_id))

        params = {
            "query": assignee_account_id,
            "includeActive": True,
            "includeInactive": False,
        }
        jira_email = jira._fetch_pages(
            User, None, "user/search", 0, 1, params)[0].email
        # Look for a status change object.
        pd_email = map_jira_user(jira_email)

        pd_user = pd_session.rget(
            '/users',
            params={'query': pd_email, 'limit': 1}
        )

        pd_session.rput(
            '/incidents/{}'.format(incident_id),
            params={
                'type': 'incident_reference',
                'assignments': [
                    {
                        'id': pd_user['id']
                    }
                ]
            }
        )

    elif event['webhookEvent'] == 'jira:issue_updated':

        issue_key = event['issue']['key']
        logger.info("Processing issue: {}".format(issue_key))

        # Look for a status change object.
        for changelog in event['changelog'].items:
            if changelog['fieldId'] == 'status':

                # found a status update, see if we should set it to something in PD
                if changelog['toString'] == JIRA_STATUS_ACKNOWLEDGED:
                    # find the corresponding PagerDuty incident ID in Dynamo
                    incident_id = get_incident_by_issue(issue_key)
                    pd_incident = pd_session.rget(
                        '/incidents/{}'.format(incident_id))

                    pdpyras.EventsAPISession(PD_EVENT_KEY).acknowledge(
                        pd_incident['dedup_key'])
                elif changelog['toString'] == JIRA_STATUS_RESOLVED:
                    # find the corresponding PagerDuty incident ID in Dynamo
                    incident_id = get_incident_by_issue(issue_key)
                    pd_incident = pd_session.rget(
                        '/incidents/{}'.format(incident_id))

                    pdpyras.EventsAPISession(PD_EVENT_KEY).resolve(
                        pd_incident['dedup_key'])

    return respond(200, event)


def respond(statusCode, response):
    """Creates a JSONy response.

    Parameters
    ----------
    statusCode : number
    body : str
    """

    logger.debug("Status Code: {}".format(statusCode))
    return {
        'statusCode': statusCode,
        'body': json.dumps(response)
    }
