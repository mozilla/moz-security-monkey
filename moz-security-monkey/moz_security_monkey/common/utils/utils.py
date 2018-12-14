"""
.. module: moz_security_monkey.common.utils.utils
    :platform: Unix
    :synopsis:

.. version:: $$VERSION$$
.. moduleauthor:: Gene Wood <gene_wood@cementhorizon.com>

"""

from security_monkey import app
import botocore.exceptions, botocore.parsers
import mozdef_client
from datetime import datetime
import json
import requests
import sys

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")

def publish_to_mozdef(summary='',
                      details={}):
    msg = mozdef_client.MozDefEvent('')
    msg.summary = summary
    msg.tags = ['asap']
    msg.details = json.loads(json.dumps(details, default=json_serial))
    region, account_id, queue_name = app.config.get(
        'SQS_QUEUE_ARN').split(':')[3:]

    msg.set_send_to_sqs(True)
    msg.set_sqs_queue_name(queue_name)
    msg.set_sqs_region(region)
    msg.set_sqs_aws_account_id(account_id)
    # Note that unlike syslog this will NEVER send to MozDef HTTP (URL is
    # ignored)
    app.logger.debug("Alerter: Sending message to SQS queue {} in account {} in region {}".format(queue_name, account_id, region))
    try:
        msg.send()
    except (botocore.exceptions.ClientError,
            botocore.parsers.ResponseParserError) as e:
        app.logger.critical(
            "Alerter: Attempt to send message to SQS queue {} in account {} "
            "in region {} failed with error {}".format(
                queue_name, account_id, region, e))

def publish_to_service_api(report_dict):
    # configuration
    service_api_url=app.config.get('service_api_url')
    auth0_url=app.config.get('auth0_url')
    client_id = app.config.get('client_id')
    client_secret = app.config.get('client_secret')

    if not service_api_url.endswith("/"):
        service_api_url= service_api_url + "/"
    # get api key:
    r=requests.post(auth0_url,
                    headers={"content-type": "application/json"},
                    data = json.dumps({"grant_type":"client_credentials",
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "audience": service_api_url})
                    )
    access_token = r.json()['access_token']
    headers={"Authorization": "Bearer {}".format(access_token)}
    result = requests.post('{}api/v1/indicator'.format(service_api_url), data=json.dumps(report_dict), headers=headers)
    if result.status_code != 200:
        sys.stderr.write('warning: serviceapi indicator post failed with code {}\n'.format(result.status_code))
        sys.stderr.write('{}\n'.format(result.text))