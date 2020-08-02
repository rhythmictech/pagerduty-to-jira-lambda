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


class NumberValidator(Validator):
    def validate(self, document):
        ok = re.match('[0-9]{4,8}$', document.text)
        if not ok:
            raise ValidationError(
                message='Invalid Number',
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

paginator = ssm.get_paginator('get_parameters_by_path')
vals = dict()
for page in paginator.paginate(Path=ssm_param_path, WithDecryption=True):
    for param in page['Parameters']:
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
        'message': 'Jira Issue Type',
        'name': 'JIRA_ISSUE_TYPE',
        'default': vals.get('JIRA_ISSUE_TYPE', 'Incident')
    },
    {
        'type': 'input',
        'message': 'Jira Additional Fields (must be in JSON format, leave as {} for none)',
        'name': 'JIRA_ADDITIONAL_FIELDS',
        'default': vals.get('JIRA_ADDITIONAL_FIELDS', '{}}')
    },
    {
        'type': 'input',
        'message': 'Jira Organization Custom Field ID',
        'name': 'JIRA_ORG_CUSTOM_FIELD_ID',
        'validate': NumberValidator,
        'default': vals.get('JIRA_ORG_CUSTOM_FIELD_ID', '')
    },
    {
        'type': 'input',
        'message': 'Jira Status - Acknowledged (set to none to ignore)',
        'name': 'JIRA_STATUS_ACKNOWLEDGED',
        'default': vals.get('JIRA_STATUS_ACKNOWLEDGED', 'none')
    },
    {
        'type': 'input',
        'message': 'Jira Status - Resolved (set to none to ignore)',
        'name': 'JIRA_STATUS_RESOLVED',
        'default': vals.get('JIRA_STATUS_RESOLVED', 'none')
    },
    {
        'type': 'input',
        'message': 'Jira Transition ID - Acknowledged (set to none for no transition)',
        'name': 'JIRA_TRANSITION_ACKNOWLEDGED',
        'default': vals.get('JIRA_TRANSITION_ACKNOWLEDGED', 'none')
    },
    {
        'type': 'input',
        'message': 'Jira Transition ID - Escalated (leave blank for no transition)',
        'name': 'JIRA_TRANSITION_ESCALATED',
        'default': vals.get('JIRA_TRANSITION_ESCALATED', 'none')
    },
    {
        'type': 'input',
        'message': 'Jira Transition ID - Resolved (leave blank for no transition)',
        'name': 'JIRA_TRANSITION_RESOLVED',
        'default': vals.get('JIRA_TRANSITION_RESOLVED', 'none')
    },
    {
        'type': 'input',
        'message': 'Jira OAUTH Access Token',
        'name': 'JIRA_OAUTH_ACCESS_TOKEN',
        'validate': AccessTokenValidator,
        'default': vals.get('JIRA_OAUTH_ACCESS_TOKEN', '')
    },
    {
        'type': 'input',
        'message': 'Jira OAUTH Access Token Secret',
        'name': 'JIRA_OAUTH_ACCESS_TOKEN_SECRET',
        'validate': AccessTokenValidator,
        'default': vals.get('JIRA_OAUTH_ACCESS_TOKEN_SECRET', '')
    },
    {
        'type': 'input',
        'message': 'Jira OAUTH Key Certificate',
        'name': 'JIRA_OAUTH_KEY_CERTIFICATE',
        'default': vals.get('JIRA_OAUTH_KEY_CERTIFICATE', '')
    },
    {
        'type': 'input',
        'message': 'PagerDuty API Key',
        'name': 'PD_API_KEY',
        'default': vals.get('PD_API_KEY', '')
    },
    {
        'type': 'confirm',
        'message': 'Enable PagerDuty forwarding (requires PD_EVENT_KEY)',
        'name': 'PD_ENABLE_PAGERDUTY_FORWARDING',
        'default': bool(vals.get('PD_ENABLE_PAGERDUTY_FORWARDING', False))
    },
    {
        'type': 'input',
        'message': 'PagerDuty Event Routing Key (optional)',
        'name': 'PD_EVENT_KEY',
        'default': vals.get('PD_EVENT_KEY', '')
    }
]

paramVals = prompt(params)

jiraUrlKey = "/pagerduty-to-jira/{}/JIRA_URL".format(STAGE)
ssm.put_parameter(Name=jiraUrlKey, Type='String', Value=paramVals['JIRA_URL'], Overwrite=True)

jiraProjectKey = "/pagerduty-to-jira/{}/JIRA_PROJECT".format(STAGE)
ssm.put_parameter(Name=jiraProjectKey, Type='String', Value=paramVals['JIRA_PROJECT'], Overwrite=True)

issueTypeKey = "/pagerduty-to-jira/{}/JIRA_ISSUE_TYPE".format(STAGE)
ssm.put_parameter(Name=issueTypeKey, Type='String', Value=paramVals['JIRA_ISSUE_TYPE'], Overwrite=True)

additionalFieldsKey = "/pagerduty-to-jira/{}/JIRA_ADDITIONAL_FIELDS".format(STAGE)
ssm.put_parameter(Name=additionalFieldsKey, Type='String', Value=paramVals['JIRA_ADDITIONAL_FIELDS'], Overwrite=True)

customFieldIdKey = "/pagerduty-to-jira/{}/JIRA_ORG_CUSTOM_FIELD_ID".format(STAGE)
ssm.put_parameter(Name=customFieldIdKey, Type='String', Value=paramVals['JIRA_ORG_CUSTOM_FIELD_ID'], Overwrite=True)

acknowledgedStatusKey = "/pagerduty-to-jira/{}/JIRA_STATUS_ACKNOWLEDGED".format(STAGE)
ssm.put_parameter(Name=acknowledgedStatusKey, Type='String', Value=paramVals['JIRA_STATUS_ACKNOWLEDGED'], Overwrite=True)

resolvedStatusKey = "/pagerduty-to-jira/{}/JIRA_STATUS_RESOLVED".format(STAGE)
ssm.put_parameter(Name=resolvedStatusKey, Type='String', Value=paramVals['JIRA_STATUS_RESOLVED'], Overwrite=True)

acknowledgedTransitionKey = "/pagerduty-to-jira/{}/JIRA_TRANSITION_ACKNOWLEDGED".format(STAGE)
ssm.put_parameter(Name=acknowledgedTransitionKey, Type='String', Value=paramVals['JIRA_TRANSITION_ACKNOWLEDGED'], Overwrite=True)

escalatedTransitionKey = "/pagerduty-to-jira/{}/JIRA_TRANSITION_ESCALATED".format(STAGE)
ssm.put_parameter(Name=escalatedTransitionKey, Type='String', Value=paramVals['JIRA_TRANSITION_ESCALATED'], Overwrite=True)

resolvedTransitionKey = "/pagerduty-to-jira/{}/JIRA_TRANSITION_RESOLVED".format(STAGE)
ssm.put_parameter(Name=resolvedTransitionKey, Type='String', Value=paramVals['JIRA_TRANSITION_RESOLVED'], Overwrite=True)

accessTokenKey = "/pagerduty-to-jira/{}/JIRA_OAUTH_ACCESS_TOKEN".format(STAGE)
ssm.put_parameter(Name=accessTokenKey, Type='String', Value=paramVals['JIRA_OAUTH_ACCESS_TOKEN'], Overwrite=True)

accessTokenSecretKey = "/pagerduty-to-jira/{}/JIRA_OAUTH_ACCESS_TOKEN_SECRET".format(STAGE)
ssm.put_parameter(Name=accessTokenSecretKey, Type='SecureString', Value=paramVals['JIRA_OAUTH_ACCESS_TOKEN_SECRET'], Overwrite=True)

keyCertificateKey = "/pagerduty-to-jira/{}/JIRA_OAUTH_KEY_CERTIFICATE".format(STAGE)
ssm.put_parameter(Name=keyCertificateKey, Type='SecureString', Value=paramVals['JIRA_OAUTH_KEY_CERTIFICATE'], Overwrite=True)

pdApiKey = "/pagerduty-to-jira/{}/PD_API_KEY".format(STAGE)
ssm.put_parameter(Name=pdApiKey, Type='SecureString', Value=paramVals['PD_API_KEY'], Overwrite=True)

pdEnableEventForwardingKey = "/pagerduty-to-jira/{}/PD_ENABLE_PAGERDUTY_FORWARDING".format(STAGE)
ssm.put_parameter(Name=pdEnableEventForwardingKey, Type='String', Value=str(paramVals['PD_ENABLE_PAGERDUTY_FORWARDING']), Overwrite=True)

pdEventKey = "/pagerduty-to-jira/{}/PD_EVENT_KEY".format(STAGE)
ssm.put_parameter(Name=pdEventKey, Type='SecureString', Value=paramVals['PD_EVENT_KEY'], Overwrite=True)


print("Parameters successfully updated")