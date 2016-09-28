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
import mozdef_client
import jinja2
import os.path


def publish_to_mozdef(summary='',
                      details={}):
    msg = mozdef_client.MozDefEvent('')
    msg.summary = summary
    msg.tags = ['asap']
    msg.details = details
    region, account_id, queue_name = app.config.get(
        'SQS_QUEUE_ARN').split(':')[3:]

    msg.set_send_to_sqs(True)
    msg.set_sqs_queue_name(queue_name)
    msg.set_sqs_region(region)
    msg.set_sqs_aws_account_id(account_id)
    # Note that unlike syslog this will NEVER send to MozDef HTTP (URL is
    # ignored)
    app.logger.debug("Alerter: Sending message to SQS queue {} in account {} in region {}".format(queue_name, account_id, region))
    msg.send()


class Alerter(security_monkey.alerter.Alerter):

    def report(self):
        """
        Collect change summaries from watchers defined and send out an email
        """
        changed_watchers = [watcher_auditor[
            0] for watcher_auditor in self.watchers_auditors if watcher_auditor[0].is_changed()]
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
            # For the time being we'll send the email body to mozdef : body
            # In the future TODO we'll send the structured data
            publish_to_mozdef(summary=subject, details={'subject': subject, 'body': body})
        return send_email(subject=subject, recipients=self.emails, html=body)
