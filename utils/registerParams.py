#!/usr/bin/env python3
from __future__ import print_function, unicode_literals
from pprint import pprint
from PyInquirer import style_from_dict, Token, prompt, Separator, Validator, ValidationError
import boto3
import re
import validators
import os

class AccessTokenValidator(Validator):
    def validate(self, document):
        ok = re.match('[a-zA-Z0-9]{32,32}$', document.text)
        if not ok:
            raise ValidationError(
                message='Invalid secret (must be 33 characters, alphanumeric))',
                cursor_position=len(document.text))  # Move cursor to end

class URLValidator(Validator):
    def validate(self, document):
        ok = validators.url(document.text)
        if not ok:
            raise ValidationError(
                message='Invalid URL',
                cursor_position=len(document.text))  # Move cursor to end


STAGE = os.getenv('STAGE', 'dev')

ssm_param_path = os.getenv('AWS_PARAMSTORE_PATH', '/pagerduty-to-jira/{}'.format(STAGE))
ssm = boto3.client('ssm')
response = ssm.get_parameters_by_path(Path=ssm_param_path, WithDecryption=True)

vals = dict()
for param in response['Parameters']:
    env_name = os.path.basename(param['Name'])
    vals[env_name] = param['Value']


params = [
    {
        'type': 'input',
        'message': 'Jira URL',
        'name': 'JIRA_URL',
        'validate': URLValidator,
        'default': vals.get('JIRA_URL', '')
    },
    {
        'type': 'input',
        'message': 'Jira Project',
        'name': 'JIRA_PROJECT',
        'default': vals.get('JIRA_PROJECT', '')
    },
    {
        'type': 'input',
        'message': 'Issue Type',
        'name': 'ISSUE_TYPE',
        'default': vals.get('ISSUE_TYPE', 'Incident')
    },
    {
        'type': 'input',
        'message': 'OAUTH Access Token',
        'name': 'OAUTH_ACCESS_TOKEN',
        'validate': AccessTokenValidator,
        'default': vals.get('OAUTH_ACCESS_TOKEN', '')
    },
    {
        'type': 'input',
        'message': 'OAUTH Access Token Secret',
        'name': 'OAUTH_ACCESS_TOKEN_SECRET',
        'validate': AccessTokenValidator,
        'default': vals.get('OAUTH_ACCESS_TOKEN_SECRET', '')
    },
    {
        'type': 'input',
        'message': 'OAUTH Key Certificate',
        'name': 'OAUTH_KEY_CERTIFICATE',
        'default': vals.get('OAUTH_KEY_CERTIFICATE', '')
    }
]

paramVals = prompt(params)

jiraUrl = "/pagerduty-to-jira/{}/JIRA_URL".format(STAGE)
ssm.put_parameter(Name=jiraUrl, Type='String', Value=paramVals['JIRA_URL'], Overwrite=True)

jiraProject = "/pagerduty-to-jira/{}/JIRA_PROJECT".format(STAGE)
ssm.put_parameter(Name=jiraProject, Type='String', Value=paramVals['JIRA_PROJECT'], Overwrite=True)

issueType = "/pagerduty-to-jira/{}/ISSUE_TYPE".format(STAGE)
ssm.put_parameter(Name=issueType, Type='String', Value=paramVals['ISSUE_TYPE'], Overwrite=True)

accessToken = "/pagerduty-to-jira/{}/OAUTH_ACCESS_TOKEN".format(STAGE)
ssm.put_parameter(Name=accessToken, Type='String', Value=paramVals['OAUTH_ACCESS_TOKEN'], Overwrite=True)

accessTokenSecret = "/pagerduty-to-jira/{}/OAUTH_ACCESS_TOKEN_SECRET".format(STAGE)
ssm.put_parameter(Name=accessTokenSecret, Type='SecureString', Value=paramVals['OAUTH_ACCESS_TOKEN_SECRET'], Overwrite=True)

keyCertificate = "/pagerduty-to-jira/{}/OAUTH_KEY_CERTIFICATE".format(STAGE)
ssm.put_parameter(Name=keyCertificate, Type='SecureString', Value=paramVals['OAUTH_KEY_CERTIFICATE'], Overwrite=True)

print("Parameters successfully updated")