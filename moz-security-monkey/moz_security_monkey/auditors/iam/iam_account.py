"""
.. module: security_monkey.auditors.iam.iam_account
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Gene Wood <gene_wood@cementhorizon.com> @gene1wood

"""
from moz_security_monkey.watchers.iam.iam_account import IAMAccount
from security_monkey.auditor import Auditor

class IAMAccountAuditor(Auditor):
    index = IAMAccount.index
    i_am_singular = IAMAccount.i_am_singular
    i_am_plural = IAMAccount.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(IAMAccountAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_no_root_mfa(self, iamaccount_item):
        """
        alert when an AWS root user has MFA disabled.
        This means a human account which could be better protected with 2FA.
        """
        mfa_enabled = iamaccount_item.config.get('AccountMFAEnabled', None)
        if not mfa_enabled:
            self.add_issue(10, 'AWS root user has no MFA device configured.', iamaccount_item)
