"""
.. module: security_monkey.auditors.cloudtrail
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Gene Wood <gene_wood@cementhorizon.com> @gene1wood

"""
from moz_security_monkey.watchers.cloudtrail import CloudTrail
from security_monkey.auditor import Auditor

class CloudTrailAuditor(Auditor):
    index = CloudTrail.index
    i_am_singular = CloudTrail.i_am_singular
    i_am_plural = CloudTrail.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(CloudTrailAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_conforming_cloudtrail_exists(self, cloudtrail_item):
        """
        alert when a fake security monkey cloudtrail item exists indicating
        that a given region has no valid conforming cloudtrail configured
        """
        if cloudtrail_item.config.get('exists', False):
            if cloudtrail_item.config.get('name') == 'NoneExists':
                self.add_issue(
                    10, "CloudTrail doesn't exist.",
                    cloudtrail_item,
                    'No API logs are being written in this region as no '
                    'CloudTrail exists')
            if cloudtrail_item.config.get('name') == 'NoConformingCloudTrailExists':
                self.add_issue(
                    10,
                    "A CloudTrail exists but it does not conform",
                    cloudtrail_item,
                    "Though a CloudTrail exists in the region it either "
                    "isn't logging, is encrypting the logs, isn't writing to "
                    "the expected bucket or isn't notifying the expected SNS "
                    "topic")
            if cloudtrail_item.config.get('name') == 'NoGlobalServiceEventTrailExists':
                self.add_issue(10,
                               "No CloudTrail is logging Global Service "
                               "Events",
                               cloudtrail_item,
                               "Across all regions, there is no CloudTrail "
                               "which is logging Global Service Events for "
                               "example IAM events")
