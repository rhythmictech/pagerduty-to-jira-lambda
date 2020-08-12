import os
import logging
import urllib
import json
import boto3
import datetime
import pdpyras
from jira import JIRA

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
client = boto3.client('ssm')
response = client.get_parameters_by_path(
    Path=ssm_param_path, WithDecryption=True)

for param in response['Parameters']:
    env_name = os.path.basename(param['Name'])
    os.environ[env_name] = param['Value']

JIRA_URL = os.environ["JIRA_URL"]
OAUTH_ACCESS_TOKEN = os.environ["OAUTH_ACCESS_TOKEN"]
OAUTH_ACCESS_TOKEN_SECRET = os.environ["OAUTH_ACCESS_TOKEN_SECRET"]
OAUTH_KEY_CERTIFICATE = os.environ["OAUTH_KEY_CERTIFICATE"]

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


def lambda_handler(event, context):
    """Lambda entry point.

    Parameters
    ----------
    event : dict
    context : dict
    """

    logger.debug("Jira event received: {}".format(event))

    issue_id = event["queryStringParameters"]['issue']
    pd_key = event["queryStringParameters"]['pdkey']

    logger.info("Processing issue: {}".format(issue_id))
    logger.info("Received pdkey: {}".format(pd_key))

    issue = jira.issue(issue_id)
    logger.debug("issue: {}".format(issue.fields))

    try:
        session = pdpyras.EventsAPISession(pd_key)

        session.trigger(issue.fields.description, "pd2jira", issue.fields.summary, "critical",
                        {
                            'links': [
                                {
                                    "href": issue.permalink(),
                                    "text": "Jira - {}".format(issue_id)
                                }
                            ]
                        })
    except PDClientError as e:
        logger.error("Failure triggering PD Event: {}".format(
            e.response.contents))
        return {"statusCode": 500, "body": e.response.contents}

    return {"statusCode": 200, "body": "OK"}
