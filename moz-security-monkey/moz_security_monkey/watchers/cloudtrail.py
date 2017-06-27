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

    MOZILLA_CLOUDTRAIL_S3_BUCKET = 'mozilla-cloudtrail-logs'
    MOZILLA_CLOUDTRAIL_SNS_TOPIC_ARN = 'arn:aws:sns:us-west-2:088944123687:MozillaCloudTrailLogs'

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

            global_service_cloudtrail_found = False
            for region in regions:
                app.logger.debug("Checking {}/{}/{}".format(
                    self.index, account, region.name))

                try:
                    cloudtrailconn = connect(
                        account, 'cloudtrail', region=region)
                   
                    cloudtrail_response = self.wrap_aws_rate_limited_call(
                        cloudtrailconn.describe_trails
                    )
                    cloudtrails = cloudtrail_response['trailList']

                except Exception as e:
                    exc = BotoConnectionIssue(
                        str(e), self.index, account, region.name)
                    self.slurp_exception(
                        (self.index, account, region.name), exc, exception_map)
                    continue

                app.logger.debug("Found {} {}".format(len(cloudtrails),
                                                      self.i_am_plural))
                if len(cloudtrails) == 0:
                    item = CloudTrailItem(region=region.name,
                                          account=account,
                                          name='NoneExists',
                                          config={'exists': False})
                    item_list.append(item)
                    continue

                # Even though this is behavior you'd see in an auditor,
                # this is the only way I can think of to look for the
                # absence of a conforming cloudtrail in a given region
                conforming_cloudtrail_found = False
                for cloudtrail in cloudtrails:
                    try:
                        cloudtrail_status = self.wrap_aws_rate_limited_call(
                            cloudtrailconn.get_trail_status,
                            cloudtrail['TrailARN']
                        )
                    except Exception as e:
                        exc = BotoConnectionIssue(str(e), self.index, account,
                                                  region.name)
                        self.slurp_exception(
                            (self.index, account, region.name), exc,
                            exception_map)
                        continue

                    item_config = {
                        'exists': True,
                        'is_logging': cloudtrail_status.get('IsLogging'),
                        'last_stop_datetime': cloudtrail_status.get('StopLoggingTime'),
                        'last_start_datetime': cloudtrail_status.get('StartLoggingTime'),
                        'last_sns_error': cloudtrail_status.get('LatestNotificationError'),
                        'last_s3_error': cloudtrail_status.get('LatestDeliveryError'),
                        'last_cloudwatch_error': cloudtrail_status.get('LatestCloudWatchLogsDeliveryError'),
                        'cloudwatch_logs_loggroup_arn': cloudtrail.get('CloudWatchLogsLogGroupArn'),
                        'cloudwatch_logs_role_arn': cloudtrail.get('CloudWatchLogsRoleArn'),
                        'include_global_service_events': cloudtrail.get('IncludeGlobalServiceEvents'),
                        'is_multi_region_trail': cloudtrail.get('IsMultiRegionTrail'),
                        'kms_key_id': cloudtrail.get('KmsKeyId'),
                        's3_bucket_name': cloudtrail.get('S3BucketName'),
                        's3_key_prefix': cloudtrail.get('S3KeyPrefix'),
                        'sns_topic_name': cloudtrail.get('SnsTopicName'),
                        'sns_topic_arn': cloudtrail.get('SnsTopicArn'),
                        'trail_arn': cloudtrail.get('TrailArn')
                    }

                    item = CloudTrailItem(region=region.name,
                                          account=account,
                                          name=cloudtrail.get(
                                              'Name', 'Unknown'),
                                          config=item_config)
                    item_list.append(item)
                    if item_config['include_global_service_events']:
                        global_service_cloudtrail_found = True

                    # Test if the trail is
                    #   actually logging
                    #   not encrypting the resulting logs
                    #   notifying the MOZILLA_CLOUDTRAIL_SNS_TOPIC_ARN topic
                    #   writing to the MOZILLA_CLOUDTRAIL_S3_BUCKET bucket
                    if (item_config['is_logging'] and
                        item_config['kms_key_id'] is None and
                        item_config['sns_topic_arn'] ==
                                self.MOZILLA_CLOUDTRAIL_SNS_TOPIC_ARN and
                        item_config['s3_bucket_name'] ==
                                self.MOZILLA_CLOUDTRAIL_S3_BUCKET):
                        conforming_cloudtrail_found = True
                if not conforming_cloudtrail_found:
                    # No CloudTrail was found in this region that conforms to
                    # the requirements
                    item = CloudTrailItem(region='universal',
                                          account=account,
                                          name='NoConformingCloudTrailExists',
                                          config={'exists': False})
                    item_list.append(item)

            if not global_service_cloudtrail_found:
                # No region is logging Global Service Events
                item = CloudTrailItem(region='universal',
                                      account=account,
                                      name='NoGlobalServiceEventTrailExists',
                                      config={'exists': False})
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
