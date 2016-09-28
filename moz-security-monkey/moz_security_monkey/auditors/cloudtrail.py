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

    def check_cloudtrail_exists(self, cloudtrail_item):
        """
        alert when a region does not have a CloudTrail.
        """
        cloudtrail_exists = cloudtrail_item.config.get('exists', False)
        if not cloudtrail_exists:
            self.add_issue(10, "CloudTrail doesn't exist.", cloudtrail_item)

    def check_cloudtrail_is_logging(self, cloudtrail_item):
        """
        alert when a region's CloudTrail isn't logging.
        """
        cloudtrail_is_logging = cloudtrail_item.config.get('is_logging', False)
        cloudtrail_exists = cloudtrail_item.config.get('exists', False)
        if cloudtrail_exists and not cloudtrail_is_logging:
            notes = ('CloudTrail logging was most recently disabled at %s.' % 
                     cloudtrail_item.config.get('last_stop_datetime', 'an unknown time'))
            self.add_issue(10, 'CloudTrail logging is disabled.', cloudtrail_item, notes)

    # TODO : Create an auditor that detects if no region has include_global_service_events
    # enabled and as a result IAM API calls aren't being recorded.