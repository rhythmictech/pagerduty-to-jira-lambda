#!/usr/bin/env python3
from __future__ import print_function, unicode_literals
import boto3
import sys
import os
import json

STAGE = os.getenv('STAGE', 'dev')

ssm_param_path = os.getenv('AWS_PARAMSTORE_PATH', '/pagerduty-to-jira/{}'.format(STAGE))
ssm = boto3.client('ssm')

paginator = ssm.get_paginator('get_parameters_by_path')
vals = dict()
for page in paginator.paginate(Path=ssm_param_path, WithDecryption=True):
    for param in page['Parameters']:
        env_name = os.path.basename(param['Name'])
        vals[env_name] = param['Value']


DYNAMODB_ENDPOINT = vals["DYNAMODB_ENDPOINT"]
DYNAMODB_REGION = vals["DYNAMODB_REGION"]
DYNAMODB_USER_TABLE = vals["DYNAMODB_USER_TABLE"]

# establish connection to dynamo
dynamodb = boto3.resource(
    'dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_ENDPOINT)
table = dynamodb.Table(DYNAMODB_USER_TABLE)

orgs = json.load(sys.stdin)

for item in orgs:
    table.put_item(Item=item)