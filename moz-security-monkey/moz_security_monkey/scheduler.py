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

from security_monkey import app, handler

import traceback
import logging
from datetime import datetime, timedelta

from security_monkey.scheduler import __prep_accounts__
from security_monkey.scheduler import _find_changes
from security_monkey.scheduler import _audit_changes
from security_monkey.scheduler import pool
from security_monkey.scheduler import scheduler

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
