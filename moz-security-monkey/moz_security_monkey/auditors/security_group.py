"""
.. module: moz_security_monkey.auditors.security_group
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

from security_monkey.auditors.security_group import SecurityGroupAuditor

ENABLED_CHECKS = ['check_securitygroup_large_port_range']

def _pass_method(*args, **kwargs):
    pass

original_method_list = dir(SecurityGroupAuditor)
for name in original_method_list:
    if name not in ENABLED_CHECKS and name.startswith('check_'):
        setattr(SecurityGroupAuditor, name, _pass_method)
