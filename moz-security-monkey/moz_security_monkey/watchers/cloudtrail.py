"""
.. module: security_monkey.watchers.cloudformation
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Gene Wood <gene_wood@cementhorizon.com> @gene1wood

"""

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.constants import TROUBLE_REGIONS
from security_monkey.exceptions import BotoConnectionIssue
from security_monkey import app
import boto.cloudtrail


class CloudTrail(Watcher):
    index = 'cloudtrail'
    i_am_singular = 'CloudTrail'
    i_am_plural = 'CloudTrails'

    def __init__(self, accounts=None, debug=False):
        super(CloudTrail, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):
        """
        :returns: item_list - list of CloudTrails.
        :returns: exception_map - A dict where the keys are a tuple containing the
            location of the exception and the value is the actual exception

        """
        self.prep_for_slurp()

        item_list = []
        exception_map = {}
        from security_monkey.common.sts_connect import connect
        for account in self.accounts:
            try:
                regions = boto.cloudtrail.regions()
            except Exception as e:  # EC2ResponseError
                exc = BotoConnectionIssue(str(e), self.index, account, None)
                self.slurp_exception((self.index, account), exc, exception_map)
                continue

            for region in regions:
                app.logger.debug("Checking {}/{}/{}".format(self.index, account, region.name))

                try:
                    cloudtrailconn = connect(account, 'cloudtrail', region=region)
                   
                    cloudtrail_response = self.wrap_aws_rate_limited_call(
                        cloudtrailconn.describe_trails
                    )
                    cloudtrails = cloudtrail_response['trailList']
                    
                    if len(cloudtrails) == 1:
                        cloudtrail = cloudtrails[0]
                        cloudtrail_status = self.wrap_aws_rate_limited_call(
                            cloudtrailconn.get_trail_status,
                            name
                        )
                    else:
                        cloudtrail = {}
                        cloudtrail_status = {}

                except Exception as e:
                    exc = BotoConnectionIssue(str(e), self.index, account, region.name)
                    self.slurp_exception((self.index, account, region.name), exc, exception_map)
                    continue

                app.logger.debug("Found {} {}".format(len(cloudtrails), self.i_am_plural))

                item_config = {
                    'exists': ('Name' in cloudtrail),
                    'is_logging': cloudtrail_status.get('IsLogging'),
                    'last_stop_datetime': cloudtrail_status.get('StopLoggingTime'),
                    'last_start_datetime': cloudtrail_status.get('StartLoggingTime'),
                    'last_sns_error': cloudtrail_status.get('LatestNotificationError'),
                    'last_s3_error': cloudtrail_status.get('LatestDeliveryError'),
                    'last_cloudwatch_error': cloudtrail_status.get('LatestCloudWatchLogsDeliveryError'),
                    'cloudwatch_logs_loggroup_arn': cloudtrail.get('CloudWatchLogsLogGroupArn'),
                    'cloudwatch_logs_role_arn': cloudtrail.get('CloudWatchLogsRoleArn'),
                    'cloudwatch_logs_role_arn': cloudtrail.get('CloudWatchLogsRoleArn'),
                    'include_global_service_events': cloudtrail.get('IncludeGlobalServiceEvents'),
                    's3_bucket_name': cloudtrail.get('S3BucketName'),
                    's3_key_prefix': cloudtrail.get('S3KeyPrefix'),
                    'sns_topic_name': cloudtrail.get('SnsTopicName'),
                }

                item = CloudTrailItem(region=region.name,
                                      account=account,
                                      name=cloudtrail.get('Name', 'Not Enabled'),
                                      config=cloudtrail)
                item_list.append(item)
                    
        return item_list, exception_map


class CloudTrailItem(ChangeItem):
    def __init__(self, region=None, account=None, name=None, config={}):
        super(CloudTrailItem, self).__init__(
            index=CloudTrail.index,
            region=region,
            account=account,
            name=name,
            new_config=config)

