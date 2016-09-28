"""
.. module: security_monkey.watchers.iam.iam_account
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Gene Wood <gene_wood@cementhorizon.com> @gene1wood

"""

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.exceptions import InvalidAWSJSON
from security_monkey.exceptions import BotoConnectionIssue
from security_monkey import app

import json
import urllib


class IAMAccount(Watcher):
    index = 'iamaccount'
    i_am_singular = 'IAM Account'
    i_am_plural = 'IAM Accounts'

    def __init__(self, accounts=None, debug=False):
        super(IAMAccount, self).__init__(accounts=accounts, debug=debug)
        self.honor_ephemerals = True
        self.ephemeral_paths = ["user$password_last_used"]

    def slurp(self):
        """
        :returns: item_dict - list of IAM Account attributes.
        :returns: exception_map - A dict where the keys are a tuple containing the
            location of the exception and the value is the actual exception
        """
        self.prep_for_slurp()
        item_list = []
        exception_map = {}

        from security_monkey.common.sts_connect import connect
        for account in self.accounts:
            try:
                iam = connect(account, 'iam')
                account_summary = self.wrap_aws_rate_limited_call(
                        iam.get_account_summary
                    )
            except Exception as e:
                exc = BotoConnectionIssue(str(e), 'iamaccount', account, None)
                self.slurp_exception((self.index, account, 'universal'), exc, exception_map)
                continue

            item_list.append(
                IAMAccountItem(account=account, name=account, config=dict(account_summary))
            )

        return item_list, exception_map


class IAMAccountItem(ChangeItem):
    def __init__(self, account=None, name=None, config={}):
        super(IAMAccountItem, self).__init__(
            index=IAMAccount.index,
            region='universal',
            account=account,
            name=name,
            new_config=config)
