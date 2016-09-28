#     Copyright 2014 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: moz_security_monkey.reporter
    :platform: Unix
    :synopsis: Runs all change watchers and auditors and uses the alerter
    to send emails for a specific account.

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

# from security_monkey.alerter import Alerter
from moz_security_monkey.alerter import Alerter
# from security_monkey.monitors import all_monitors
from moz_security_monkey.monitors import all_monitors
from security_monkey import app, db

import security_monkey.reporter

class Reporter(security_monkey.reporter.Reporter):
    """Sets up all watchers and auditors and the alerters"""

    def __init__(self, accounts=None, alert_accounts=None, debug=False):
        self.account_watchers = {}
        self.account_alerters = {}
        if not alert_accounts:
            alert_accounts = accounts
        for account in accounts:
            self.account_watchers[account] = []
            for monitor in all_monitors():
                watcher = monitor.watcher_class(accounts=[account], debug=debug)
                auditor = monitor.auditor_class(accounts=[account], debug=debug) if monitor.has_auditor() else None
                self.account_watchers[account].append((watcher, auditor))

            if account in alert_accounts:
                self.account_alerters[account] = Alerter(watchers_auditors=self.account_watchers[account], account=account)
