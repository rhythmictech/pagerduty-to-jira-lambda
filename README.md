# PagerDuty to Jira

This project integrates PagerDuty with Jira using the PagerDuty v2 Webhook API, AWS EventBridge, AWS Lambda and AWS Dynamo. It is intended to provide more robust and customizable integration than is possible using the native Jira Cloud integration. Additionally, many integrations can be configured between PagerDuty and Jira Cloud. The native integration only supports a 1:1 mapping between PagerDity and Jira Cloud instances.

- pd2jira - Lambda code
- events - Test events
- tests - Unit tests
- utils - script to configure AWS Parameter Store with appropriate values.
- template.yaml - CloudFormation template


## Installation

This integration must be authorized in Jira, which requires creating an application link and configuring OAuth. OAuth tokens can be used across multiple deployments of this function.

Create an SSL key:

```
openssl genrsa -out rsa.pem 2048
openssl rsa -in rsa.pem -pubout -out rsa.pub
```

In Jira Cloud, create an application link. Use a fake URL.

On the Link applications page, set values as follows:

* Application Name - meaningful description
* Application Type - generic application
* Create incoming link - checked

All other fields remain blank. Click continue.

Fill in "pagerduty-to-jira" for Consumer Key. Consumer Name should be the same as Application Name.

Paste the contents of rsa.pub.

Configure oauth:

```
jirashell -s https://rhythmic.atlassian.net --consumer-key pagerduty-to-jira --key-cert rsa.pem --oauth-dance
```

Inside the shell, run `oauth` and note the corresponding values.

Run `STAGE=production utils/registerParams.py` and enter the appropriate values. STAGE can be any environment prefix you prefer.

Deploy to AWS:

```bash
sam deploy --guided --capabilities CAPABILITY_IAM
```

You will be prompted for the following:

* **Stack Name**: Name of CloudFormation stack (e.g., `pagerduty-to-jira`).
* **AWS Region**: AWS Region (e.g., `us-east-1`).
* **Confirm changes before deploy**: Select yes to review and confirm a change set.
* **Save arguments to samconfig.toml**: Set to yes to save these values for future deployments.

## View Logs

```bash
pagerduty-to-jira$ sam logs -n PagerDutyToJiraFunction --stack-name pagerduty-to-jira --tail
```

## Develop

Build the application with the `sam build --use-container` command.

```bash
pagerduty-to-jira$ sam build --use-container
```

Run functions locally and invoke them with the `sam local invoke` command.

```bash
pagerduty-to-jira$ sam local invoke PagerDutyToFunction --event events/event.json
```

## Unit tests

Tests are defined in the `tests` folder in this project. Use PIP to install the [pytest](https://docs.pytest.org/en/latest/) and run unit tests.

```bash
pagerduty-to-jira$ pip install pytest pytest-mock --user
pagerduty-to-jira$ python -m pytest tests/ -v
```

## Cleanup

To delete the sample application that you created, use the AWS CLI. Assuming you used your project name for the stack name, you can run the following:

```bash
aws cloudformation delete-stack --stack-name pagerduty-to-jira
```

## Requirements
* [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
* [Python 3.x](https://www.python.org/downloads/)
* [Docker](https://hub.docker.com/search/?type=edition&offering=community)
