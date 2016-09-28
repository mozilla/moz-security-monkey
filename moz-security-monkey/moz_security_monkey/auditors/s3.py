"""
.. module: moz_security_monkey.auditors.s3
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

from security_monkey.auditors.s3 import S3Auditor

ENABLED_CHECKS = ['check_policy']

def _pass_method(*args, **kwargs):
    pass

original_method_list = dir(S3Auditor)
for name in original_method_list:
    if name not in ENABLED_CHECKS and name.startswith('check_'):
        setattr(S3Auditor, name, _pass_method)
