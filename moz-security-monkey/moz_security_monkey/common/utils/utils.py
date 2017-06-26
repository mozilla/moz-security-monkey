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
