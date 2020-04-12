import os
import logging
import urllib
import json
import boto3
import datetime
from jira import JIRA

logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', logging.DEBUG))

for handler in logger.handlers:
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s](%(name)s) %(message)s'))

for lib_logger in ['botocore', 'boto3', 'jira', 'requests_oauthlib', 'oauthlib', 'urllib3']:
    logging.getLogger(lib_logger).setLevel(
        os.environ.get('LIBRARY_LOG_LEVEL', logging.ERROR))

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
print(jira.server_info())
logger.info("Connected to Jira: {}".format(jira.server_info()))

# establish connection to dynamo
dynamodb = boto3.resource(
    'dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_ENDPOINT)
table = dynamodb.Table(DYNAMODB_TABLE)


def trigger(pd_event):
    """Creates and links a Jira for a new incident in PagerDuty.

    Parameters
    ----------
    pd_event : dict
        The unwrapped PagerDuty event from the webhook call
    """

    description = """
*Incident Description*: %s
*Service*: %s

    """ % (pd_event['incident']['description'], pd_event['incident']['service']['name'])

    issue_fields = {
        'project': JIRA_PROJECT,
        'summary': 'Alert - {}'.format(pd_event['incident']['title']),
        'description': description,
        'issuetype': {'name': ISSUE_TYPE}
    }

    issue = jira.create_issue(fields=issue_fields)
    jira.add_comment(
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


def annotate(pd_event):
    """Adds a note to a Jira if it can be found. Returns a 404 if the 
    PagerDuty incident could not be matched to an existing Jira.

    Parameters
    ----------
    pd_event : dict
        The unwrapped PagerDuty event from the webhook call
    """

    message = """
%s

Note: %s
    """ % (pd_event['log_entries'][0]['summary'], pd_event['log_entries'][0]['channel']['content'])

    return handle_comment_on_incident(pd_event['incident']['id'], message)

def state_change(state_change, pd_event):
    """Handles a simple state change by adding the provided log entry as a 
    comment.

    Parameters
    ----------
    stage_change : str
        Specify the type of state change (not currently used)
    pd_event : dict
        The unwrapped PagerDuty event from the webhook call
    """

    return handle_comment_on_incident(pd_event['incident']['id'], pd_event['log_entries'][0]['summary'])


def handle_comment_on_incident(incident_id, message):
    """Wrapper method to simplify adding a comment.

    Most webhook events result in the same basic behavior. Find a linked Jira
    and add a comment. This function encapsulates that for better readability.
    It automatically returns a RESTfully appropriate response.

    Parameters
    ----------
    incident_id : str
        PagerDuty Incident ID
    message : str
        Comment body
    """
    try:
        issuekey = get_issue_by_incident(incident_id)

    except boto3.ClientError as e:
        logger.error(e.response['Error']['Message'])
        return respond(503, e.response['Error']['Message'])

    if issuekey is None:
        logger.warn("Incident mapping not found for {}".format(incident_id))
        return respond(404, "Not Found")

    comment_on_issue(issuekey, message)

    return respond(200, "OK")


def unsupported(pd_event):
    """Handles unsupported PagerDuty webhook requests. Logs the type.

    Parameters
    ----------
    pd_event : dict
        The unwrapped PagerDuty event from the webhook call
    """

    logger.error(
        "Received unsupported event type: {}".format(pd_event['event']))
    return respond(402, "Unsupported Event Type")


def get_issue_by_incident(incidentid):
    """Query DynamoDB to find linked Jira issue.

    Returns `None` if a linked issue cannot be found.

    Parameters
    ----------
    incidentid : str
        PagerDuty Incident ID
    """

    response = table.get_item(Key={'incidentid': incidentid } )

    try:
        item = response['Item']
        logger.debug("Incident mapping found: {}".format(json.dumps(item)))
        return item['issuekey']
    except KeyError:
        pass


def comment_on_issue(issuekey, comment):
    """Adds a comment to the specified issue.

    Parameters
    ----------
    issuekey : str
        Jira Issue Key
    comment
        Comment to add to Jira
    """

    issue = jira.issue(issuekey)
    jira.add_comment(
        issue.key, comment)


def lambda_handler(event, context):
    """Lambda entry point.

    Parameters
    ----------
    event : dict
    context : dict
    """

    logger.debug("PagerDuty event received: {}".format(
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
    """Creates a JSONy response.

    Parameters
    ----------
    statusCode : number
    body : str
    """

    logger.debug("Status Code: {}".format(statusCode))
    return {
        'statusCode': statusCode,
        'body': body
    }
