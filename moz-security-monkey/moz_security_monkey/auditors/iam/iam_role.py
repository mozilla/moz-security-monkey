"""
.. module: moz_security_monkey.auditors.iam_role
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

from security_monkey.auditors.iam_role import IAMRoleAuditor

ENABLED_CHECKS = ['check_star_assume_role_policy']

def _pass_method(*args, **kwargs):
    pass

original_method_list = dir(IAMRoleAuditor)
for name in original_method_list:
    if name not in ENABLED_CHECKS and name.startswith('check_'):
        setattr(IAMRoleAuditor, name, _pass_method)
