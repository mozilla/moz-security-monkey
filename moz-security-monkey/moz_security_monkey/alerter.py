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
            watchers = [
                {'created_items': [
                    {'account': new_item.account,
                     'region': new_item.region,
                     'name': new_item.name,
                     'issues': {
                         'new': [
                             {'score': issue.score,
                              'issue': issue.issue,
                              'notes': issue.notes,
                              'justification': {
                                  'justified': issue.justified,
                                  'user_name': (issue.user.name
                                                if issue.user is not None
                                                else None),
                                  'user_email': (issue.user.email
                                                 if issue.user is not None
                                                 else None),
                                  'date': issue.justified_date,
                                  'justification': issue.justification}}
                             for issue in new_item.confirmed_new_issues],
                         'fixed': [
                             {'score': issue.score,
                              'issue': issue.issue,
                              'notes': issue.notes,
                              'justification': {
                                  'justified': issue.justified,
                                  'user_name': (issue.user.name
                                                if issue.user is not None
                                                else None),
                                  'user_email': (issue.user.email
                                                 if issue.user is not None
                                                 else None),
                                  'date': issue.justified_date,
                                  'justification': issue.justification}}
                             for issue in new_item.confirmed_fixed_issues],
                         'existing': [
                             {'score': issue.score,
                              'issue': issue.issue,
                              'notes': issue.notes,
                              'justification': {
                                  'justified': issue.justified,
                                  'user_name': (issue.user.name
                                                if issue.user is not None
                                                else None),
                                  'user_email': (issue.user.email
                                                 if issue.user is not None
                                                 else None),
                                  'date': issue.justified_date,
                                  'justification': issue.justification}}
                             for issue in new_item.confirmed_existing_issues]
                     }
                     }
                    for new_item in (watcher.created_items if
                                     watcher.created() else [])],
                 'changed_items': [
                     {'account': new_item.account,
                      'region': new_item.region,
                      'name': new_item.name,
                      'issues': {
                          'new': [
                              {'score': issue.score,
                               'issue': issue.issue,
                               'notes': issue.notes,
                               'justification': {
                                   'justified': issue.justified,
                                   'user_name': (issue.user.name
                                                 if issue.user is not None
                                                 else None),
                                   'user_email': (issue.user.email
                                                  if issue.user is not None
                                                  else None),
                                   'date': issue.justified_date,
                                   'justification': issue.justification}}
                              for issue in new_item.confirmed_new_issues],
                          'fixed': [
                              {'score': issue.score,
                               'issue': issue.issue,
                               'notes': issue.notes,
                               'justification': {
                                   'justified': issue.justified,
                                   'user_name': (issue.user.name
                                                 if issue.user is not None
                                                 else None),
                                   'user_email': (issue.user.email
                                                  if issue.user is not None
                                                  else None),
                                   'date': issue.justified_date,
                                   'justification': issue.justification}}
                              for issue in new_item.confirmed_fixed_issues],
                          'existing': [
                              {'score': issue.score,
                               'issue': issue.issue,
                               'notes': issue.notes,
                               'justification': {
                                   'justified': issue.justified,
                                   'user_name': (issue.user.name
                                                 if issue.user is not None
                                                 else None),
                                   'user_email': (issue.user.email
                                                  if issue.user is not None
                                                  else None),
                                   'date': issue.justified_date,
                                   'justification': issue.justification}}
                              for issue in new_item.confirmed_existing_issues]
                      }
                      }
                     for new_item in (watcher.changed_items if
                                      watcher.changed() else [])],

                 'deleted_items': [
                     {'account': new_item.account,
                      'region': new_item.region,
                      'name': new_item.name,
                      'issues': {
                          'new': [
                              {'score': issue.score,
                               'issue': issue.issue,
                               'notes': issue.notes,
                               'justification': {
                                   'justified': issue.justified,
                                   'user_name': (issue.user.name
                                                 if issue.user is not None
                                                 else None),
                                   'user_email': (issue.user.email
                                                  if issue.user is not None
                                                  else None),
                                   'date': issue.justified_date,
                                   'justification': issue.justification}}
                              for issue in new_item.confirmed_new_issues],
                          'fixed': [
                              {'score': issue.score,
                               'issue': issue.issue,
                               'notes': issue.notes,
                               'justification': {
                                   'justified': issue.justified,
                                   'user_name': (issue.user.name
                                                 if issue.user is not None
                                                 else None),
                                   'user_email': (issue.user.email
                                                  if issue.user is not None
                                                  else None),
                                   'date': issue.justified_date,
                                   'justification': issue.justification}}
                              for issue in new_item.confirmed_fixed_issues],
                          'existing': [
                              {'score': issue.score,
                               'issue': issue.issue,
                               'notes': issue.notes,
                               'justification': {
                                   'justified': issue.justified,
                                   'user_name': (issue.user.name
                                                 if issue.user is not None
                                                 else None),
                                   'user_email': (issue.user.email
                                                  if issue.user is not None
                                                  else None),
                                   'date': issue.justified_date,
                                   'justification': issue.justification}}
                              for issue in new_item.confirmed_existing_issues]
                      }
                      }
                     for new_item in (watcher.deleted_items if
                                      watcher.deleted() else [])]
                 }
                for watcher in
                changed_watchers]
            publish_to_mozdef(summary=subject,
                              details={'subject': subject,
                                       'watchers': watchers})
        return send_email(subject=subject, recipients=self.emails, html=body)
