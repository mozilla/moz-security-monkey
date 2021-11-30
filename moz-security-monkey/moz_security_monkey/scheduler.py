"""
.. module: moz_security_monkey.scheduler
    :platform: Unix
    :synopsis: Runs watchers, auditors, or reports on demand or on a schedule

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

from apscheduler.threadpool import ThreadPool
from apscheduler.scheduler import Scheduler

from security_monkey.datastore import Account
# from security_monkey.monitors import all_monitors, get_monitor
# from security_monkey.reporter import Reporter
from moz_security_monkey.monitors import all_monitors, get_monitor
from moz_security_monkey.reporter import Reporter

from security_monkey import app, db, handler

import traceback
import logging
from datetime import datetime, timedelta

from security_monkey.scheduler import __prep_accounts__
from security_monkey.scheduler import _find_changes
# from security_monkey.scheduler import _audit_changes
from security_monkey.scheduler import pool
from security_monkey.scheduler import scheduler
from moz_security_monkey.common.utils.utils import publish_to_mozdef

def __prep_monitor_names__(monitor_names):
    if monitor_names == 'all':
        return [monitor.index for monitor in all_monitors()]
    else:
        return monitor_names.split(',')

def run_change_reporter(accounts, interval=None):
    """ Runs Reporter """
    accounts = __prep_accounts__(accounts)
    reporter = Reporter(accounts=accounts, alert_accounts=accounts, debug=True)
    for account in accounts:
        reporter.run(account, interval)

def find_changes(accounts, monitor_names, debug=True):
    monitor_names = __prep_monitor_names__(monitor_names)
    for monitor_name in monitor_names:
        monitor = get_monitor(monitor_name)
        _find_changes(accounts, monitor, debug)

def audit_changes(accounts, monitor_names, send_report, debug=True):
    monitor_names = __prep_monitor_names__(monitor_names)
    accounts = __prep_accounts__(accounts)
    auditors = []
    for monitor_name in monitor_names:
        monitor = get_monitor(monitor_name)
        if monitor.has_auditor():
            auditors.append(monitor.auditor_class(accounts=accounts, debug=True))
    if auditors:
        _audit_changes(accounts, auditors, send_report, debug)

def _audit_changes(accounts, auditors, send_report, debug=True):
    """ Runs auditors on all items """
    for au in auditors:
        au.audit_all_objects()
        if send_report:

            for item in au.items:
                item.totalscore = 0
                for issue in item.audit_issues:
                    item.totalscore = item.totalscore + issue.score
            sorted_list = sorted(au.items, key=lambda item: item.totalscore)
            sorted_list.reverse()
            report_list = []
            for item in sorted_list:
                if item.totalscore > 0:
                    report_list.append(item)
                else:
                    break
            if len(report_list) > 0:
                subject = "Security Monkey {} Auditor Report".format(
                    au.i_am_singular)
                for item in report_list:
                    details = {
                        'subject': subject,
                        'account': item.account,
                        'region': item.region,
                        'index': item.index,
                        'name': item.name,
                        'totalscore': item.totalscore}
                    issues = []
                    for issue in item.audit_issues:
                        audit_issue = {
                            'score': issue.score,
                            'issue': issue.issue,
                            'notes': issue.notes}
                        if issue.justified:
                            audit_issue['justification'] = {
                                'user_name': (issue.user.name
                                              if issue.user is not None
                                              else None),
                                'user_email': (issue.user.email
                                               if issue.user is not None
                                               else None),
                                'date': issue.justified_date,
                                'justification': issue.justification}
                        issues.append(audit_issue)
                    if len(issues) > 0:
                        details['issues'] = {}
                        i = 0
                        for issue in issues:
                            i += 1
                            details['issues'][i] = issue
                    publish_to_mozdef(
                        summary=subject,
                        details=details)
                app.logger.info(
                    "Auditor reports published to MozDef with {} "
                    "entries.".format(len(report_list)))
        au.save_issues()
    db.session.close()


def setup_scheduler():
    """Sets up the APScheduler"""
    log = logging.getLogger('apscheduler')
    log.setLevel(app.config.get('LOG_LEVEL'))
    log.addHandler(handler)

    try:
        accounts = Account.query.filter(Account.third_party==False).filter(Account.active==True).all()
        accounts = [account.name for account in accounts]
        for account in accounts:
            print "Scheduler adding account {}".format(account)
            rep = Reporter(accounts=[account])
            for period in rep.get_intervals(account):
                scheduler.add_interval_job(
                    run_change_reporter,
                    minutes=period,
                    start_date=datetime.now()+timedelta(seconds=2),
                    args=[account, period]
                )
            auditors = [a for (_, a) in rep.get_watchauditors(account) if a]
            if auditors:
                scheduler.add_cron_job(_audit_changes, hour=10, day_of_week="mon-fri", args=[account, auditors, True])

    except Exception as e:
        app.logger.warn("Scheduler Exception: {}".format(e))
        app.logger.warn(traceback.format_exc())
