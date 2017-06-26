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
.. module: security_monkey.alerter
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netfilx.com> @monkeysecurity

"""

from security_monkey import app
from security_monkey.common.jinja import get_jinja_env
from security_monkey.datastore import User
from security_monkey.common.utils.utils import send_email
from security_monkey.alerter import get_subject, report_content
import security_monkey.alerter
import jinja2
import os.path
from moz_security_monkey.common.utils.utils import publish_to_mozdef


def get_summary(
        has_issues, has_new_issue, has_unjustified_issue, account,
        watcher_str):
    if has_new_issue:
        return "NEW ISSUE - [{}] Changes in {}".format(account, watcher_str)
    elif has_issues and has_unjustified_issue:
        return "[{}] Changes w/existing issues in {}".format(account, watcher_str)
    elif has_issues and not has_unjustified_issue:
        return "[{}] Changes w/justified issues in {}".format(account, watcher_str)
    else:
        return "[{}] Changes in {}".format(account, watcher_str)


class Alerter(security_monkey.alerter.Alerter):

    def report(self):
        """
        Collect change summaries from watchers defined and send out an email
        """
        changed_watchers = [
            watcher_auditor[0]
            for watcher_auditor
            in self.watchers_auditors if watcher_auditor[0].is_changed()]
        has_issues = has_new_issue = has_unjustified_issue = False
        for watcher in changed_watchers:
            (has_issues, has_new_issue,
             has_unjustified_issue) = watcher.issues_found()
            if has_issues:
                users = User.query.filter(User.accounts.any(name=self.account)).filter(
                    User.change_reports == 'ISSUES').all()
                new_emails = [user.email for user in users]
                self.emails.extend(new_emails)
                break

        watcher_types = [watcher.index for watcher in changed_watchers]
        watcher_str = ', '.join(watcher_types)
        if len(changed_watchers) == 0:
            app.logger.info("Alerter: no changes found")
            return

        app.logger.info(
            "Alerter: Found some changes in {}: {}".format(self.account, watcher_str))
        content = {u'watchers': changed_watchers}
        body = report_content(content)
        subject = get_subject(
            has_issues, has_new_issue, has_unjustified_issue, self.account, watcher_str)
        if app.config.get('SQS_QUEUE_ARN'):
            # Intentionally leaving out new_item.get_pdiff_html() as we
            # don't need it

            for watcher in changed_watchers:
                for action in ["created", "changed", "deleted"]:
                    for new_item in (
                            getattr(watcher, action + "_items")
                            if getattr(watcher, action)() else
                            []):
                        issues = []
                        for issue_type in ["new", "fixed", "existing"]:
                            for issue_obj in getattr(
                                    new_item, "confirmed_" +
                                    issue_type + "_issues"):
                                issue = {
                                    'type': issue_type,
                                    'score': issue_obj.score,
                                    'issue': issue_obj.issue,
                                    'notes': issue_obj.notes}
                                if issue_obj.justified:
                                    issue['justification'] = {
                                        'user_name': (
                                            issue_obj.user.name
                                            if issue_obj.user is not None
                                            else None),
                                        'user_email': (
                                            issue_obj.user.email
                                            if issue_obj.user is not None
                                            else None),
                                        'date': issue_obj.justified_date,
                                        'justification': issue_obj.justification
                                    }
                                issues.append(issue)
                        (has_issues,
                         has_new_issue,
                         has_unjustified_issue) = watcher.issues_found()
                        details = {'account_name': new_item.account,
                                   'region': new_item.region,
                                   'name': new_item.name,
                                   'action': action,
                                   'watcher': watcher.index,
                                   'has_issues': has_issues,
                                   'has_new_issue': has_new_issue,
                                   'has_unjustified_issue': has_unjustified_issue}
                        summary = get_summary(
                            has_issues,
                            has_new_issue,
                            has_unjustified_issue,
                            self.account,
                            watcher.index
                        )
                        if len(issues) > 0:
                            details['issues'] = {}
                            i = 0
                            for issue in issues:
                                i += 1
                                details['issues'][i] = issue
                            # If there are no issues with an item,
                            # don't publish to mozdef
                            # This behaviour deviates from the default
                            # security monkey which emails items that have
                            # no issues
                            publish_to_mozdef(summary=summary,
                                              details=details)
        return True
        # return send_email(subject=subject, recipients=self.emails, html=body)
