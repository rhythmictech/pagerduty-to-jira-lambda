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

# Set JIRA general vars
JIRA_URL = os.environ["JIRA_URL"]
JIRA_PROJECT = os.environ["JIRA_PROJECT"]
JIRA_ISSUE_TYPE = os.environ["JIRA_ISSUE_TYPE"]
JIRA_ADDITIONAL_FIELDS = os.environ["JIRA_ADDITIONAL_FIELDS"]
JIRA_ORG_FIELD = "customfield_{}".format(
    os.environ["JIRA_ORG_CUSTOM_FIELD_ID"])

# Jira statuses
JIRA_TRANSITION_ACKNOWLEDGED = os.environ["JIRA_TRANSITION_ACKNOWLEDGED"]
JIRA_TRANSITION_ESCALATED = os.environ["JIRA_TRANSITION_ESCALATED"]
JIRA_TRANSITION_RESOLVED = os.environ["JIRA_TRANSITION_RESOLVED"]

# Jira access
OAUTH_ACCESS_TOKEN = os.environ["JIRA_OAUTH_ACCESS_TOKEN"]
OAUTH_ACCESS_TOKEN_SECRET = os.environ["JIRA_OAUTH_ACCESS_TOKEN_SECRET"]
OAUTH_KEY_CERTIFICATE = os.environ["JIRA_OAUTH_KEY_CERTIFICATE"]

# Dynamo related vars
DYNAMODB_ENDPOINT = os.environ["DYNAMODB_ENDPOINT"]
DYNAMODB_REGION = os.environ["DYNAMODB_REGION"]
DYNAMODB_ISSUE_TABLE = os.environ["DYNAMODB_ISSUE_TABLE"]
DYNAMODB_USER_TABLE = os.environ["DYNAMODB_USER_TABLE"]
DYNAMODB_ORGANIZATION_TABLE = os.environ["DYNAMODB_ORGANIZATION_TABLE"]

# PD related vars
PD_API_KEY = os.environ["PD_API_KEY"]

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
issue_table = dynamodb.Table(DYNAMODB_ISSUE_TABLE)
org_table = dynamodb.Table(DYNAMODB_ORGANIZATION_TABLE)
user_table = dynamodb.Table(DYNAMODB_USER_TABLE)

# configure pdpyras
pd_session = pdpyras.APISession(PD_API_KEY)


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


def assign_incident(pd_event):
    """Updates the assignee in Jira when reassigned in PD

    Parameters
    ----------

    pd_event : dict
        The unwrapped PagerDuty event from the webhook call
    """

    incident_id = pd_event['incident']['id']
    try:
        issuekey = get_issue_by_incident(incident_id)

    except boto3.ClientError as e:
        logger.error(e.response['Error']['Message'])
        return respond(503, e.response['Error']['Message'])

    if issuekey is None:
        logger.warn("Incident mapping not found for {}".format(incident_id))
        return respond(404, "Not Found")

    # Map the PD Incident assignee to a Jira user if possible
    assignee_email = None
    try:
        user_id = pd_event['incident']['assignments'][0]['assignee']['id']
        user = pd_session.rget('/users/{}'.format(user_id))
        assignee_email = user['email']

        assign_issue(issuekey, map_pagerduty_user(assignee_email))

    except KeyError:
        logger.debug("Error assigning issue: no human assignee found")
        pass

    return handle_comment_on_incident(pd_event['incident']['id'], pd_event['log_entries'][0]['summary'])


def assign_issue(issuekey, assignee_email):
    """The `jira-python` project has a busted implementation of search_users,
    which in turn causes assign_issue to fail. This is due to Atlassian phasing 
    out the username field for GDPR. This hacky hack deals with that.

    Parameters
    ----------
    issuekey : str
        Jira Issue Key
    assignee_email
        Email address of user to assign issue to
    """
    try:
        logger.debug(
            "Attempting to find accountId for user {}".format(assignee_email))

        params = {
            "query": assignee_email,
            "includeActive": True,
            "includeInactive": False,
        }
        account_id = jira._fetch_pages(
            User, None, "user/search", 0, 1, params)[0].accountId

        url = (
            jira._options["server"]
            + "/rest/api/latest/issue/"
            + str(issuekey)
            + "/assignee"
        )
        payload = {"accountId": account_id}
        jira._session.put(url, data=json.dumps(payload))

    except IndexError:
        logger.info("Could not find user in Jira")


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


def get_additional_fields():
    """Get additional fields to add to a Jira issue in dict format
    """

    return json.loads(JIRA_ADDITIONAL_FIELDS)


def get_issue_by_incident(incidentid):
    """Query DynamoDB to find linked Jira issue.

    Returns `None` if a linked issue cannot be found.

    Parameters
    ----------
    incidentid : str
        PagerDuty Incident ID
    """

    response = issue_table.get_item(Key={'incidentid': incidentid})

    try:
        item = response['Item']
        logger.debug("Incident mapping found: {}".format(json.dumps(item)))
        return item['issuekey']
    except KeyError:
        pass


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


def map_pagerduty_user(email):
    """Query DynamoDB to find a PD user mapping. If not found, the original address is returned.

    Parameters
    ----------
    email : str
        Email address of user
    """

    response = user_table.get_item(Key={'pd_email': email})

    try:
        item = response['Item']
        logger.debug("User mapping found: {}".format(json.dumps(item)))
        return item['jira_email']
    except KeyError:
        return email


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

    # Determine if a state change should be performed
    if state_change == "acknowledge" and JIRA_TRANSITION_ACKNOWLEDGED != "none":
        transition_issue(pd_event['incident']
                           ['id'], JIRA_TRANSITION_ACKNOWLEDGED)
    elif state_change == "escalate" and JIRA_TRANSITION_ESCALATED != "none":
        transition_issue(pd_event['incident']
                           ['id'], JIRA_TRANSITION_ESCALATED)
    elif state_change == "resolve" and JIRA_TRANSITION_RESOLVED != "none":
        transition_issue(pd_event['incident']
                           ['id'], JIRA_TRANSITION_RESOLVED)

    return handle_comment_on_incident(pd_event['incident']['id'], pd_event['log_entries'][0]['summary'])


def transition_issue(incident_id, transition_id):
    """Wrapper method to simplify updating status in a Jira

    Most webhook events result in the same basic behavior. Find a linked Jira
    and add a comment. This function encapsulates that for better readability.
    It automatically returns a RESTfully appropriate response.

    Parameters
    ----------
    incident_id : str
        PagerDuty Incident ID
    transition_id : int
        ID of Jira transition
    """
    try:
        issuekey = get_issue_by_incident(incident_id)

    except boto3.ClientError as e:
        logger.error(e.response['Error']['Message'])
        raise e

    if issuekey is None:
        logger.warn("Incident mapping not found for {}".format(incident_id))
        pass

    jira.transition_issue(issuekey, int(transition_id))


def trigger(pd_event):
    """Creates and links a Jira for a new incident in PagerDuty.

    Parameters
    ----------
    pd_event : dict
        The unwrapped PagerDuty event from the webhook call
    """

    incident_id = pd_event['incident']['id']

    description = """
h3. Incident Summary
%s
h3. Service
%s

    """ % (pd_event['incident']['description'], pd_event['incident']['service']['name'])

    # attempt to extract CEF data from the log
    try:
        cef_details = pd_event['log_entries'][0]['channel']['cef_details']

        detail_table = [description, "h3. CEF Details\n||Attribute||Value||"]
        for key, value in cef_details['details'].items():
            detail_table.append("|{}|{}|".format(key, value))

        description = '\n'.join(detail_table)

    except KeyError:
        logger.debug(
            "Could not extract CEF Data for incident {}".format(incident_id))
        pass

    issue_fields = {
        'reporter': {'name': 'Anonymous'},
        'project': JIRA_PROJECT,
        'summary': 'Alert - {}'.format(pd_event['incident']['title']),
        'description': description,
        'issuetype': {'name': JIRA_ISSUE_TYPE}
    }

    # Map the PD Service to an organization if possible
    try:
        pd_service = pd_event['incident']['service']['name']
        logger.debug(
            "Attempting to match service to organization: {}".format(pd_service))

        # find the service in dynamo
        response = org_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key(
                'pd_service').eq(pd_service)
        )

        org_id = int(response['Items'][0]['organization_id'])
        logger.debug("Organization ID found: {}".format(org_id))
        issue_fields[JIRA_ORG_FIELD] = [org_id]

    except KeyError:
        logger.debug("Could not find organization mapping")
        pass
    except IndexError:
        logger.debug("Could not find organization mapping")
        pass

    # Create the issue, merging in any custom fields
    issue = jira.create_issue(fields={**issue_fields, **get_additional_fields()})

    # Add a comment with status update
    jira.add_comment(
        issue.key, 'Alert triggered by PagerDutyToJira integration')

    # Add PD link
    link_fields = {
        'url': pd_event['incident']['html_url'],
        'title': 'PagerDuty Incident'
    }
    jira.add_simple_link(issue.key, link_fields)

    # Add an assignee if possible
    # Map the PD Incident assignee to a Jira user if possible
    assignee_email = None
    try:
        user_id = pd_event['incident']['assignments'][0]['assignee']['id']
        user = pd_session.rget('/users/{}'.format(user_id))
        assignee_email = user['email']

        assign_issue(issue.key, map_pagerduty_user(assignee_email))

    except KeyError:
        logger.debug("Error adding note: no human assignee found")
        pass

    # Record item mapping in DynamoDB
    issue_table.put_item(
        Item={
            'incidentid': incident_id,
            'issuekey': issue.key,
            'trigger_date': datetime.datetime.utcnow().isoformat()
        }
    )

    # In order to post-back a Jira link, we need to create a note. Notes have
    # to include an email address associated with a valid user. To make this work,
    # we will attempt to get the email address of the user assigned the incident
    # which isn't always possible..
    # TODO allow for a fixed email address to be specified as a parameter.
    if assignee_email != None:
        try:
            headers = {}
            headers['From'] = assignee_email
            pd_session.rpost(
                "/incidents/{}/notes".format(pd_event['incident']['id']),
                json={
                    "note": {"content": "Jira Link: {}".format(issue.permalink())}},
                headers=headers)

        except pdpyras.PDClientError as e:
            logger.warn("Error adding note: {} ".format(e.response.content))


def unsupported(pd_event):
    """Handles unsupported PagerDuty webhook requests. Logs the type.

    Parameters
    ----------
    pd_event : dict
        The unwrapped PagerDuty event from the webhook call
    """

    logger.error(
        "Received unsupported event type: {}".format(pd_event['event']))


def lambda_handler(event, context):
    """Lambda entry point.

    Parameters
    ----------
    event : dict
    context : dict
    """

    logger.debug("PagerDuty event received: {}".format(
        event))

    for pd_event in event['messages']:
        switcher = {
            'incident.acknowledge': lambda: state_change('acknowledge', pd_event),
            'incident.annotate': lambda: annotate(pd_event),
            'incident.assign': lambda: assign_incident(pd_event),
            'incident.escalate': lambda: state_change('escalate', pd_event),
            'incident.resolve': lambda: state_change('resolve', pd_event),
            'incident.trigger': lambda: trigger(pd_event),
            'incident.unacknowledge': lambda: state_change('uncknowledge', pd_event)
        }

        func = switcher.get(pd_event['event'],
                            lambda: unsupported(pd_event))

        func()

    return respond(200, "OK")
