"""
.. module: moz_security_monkey.monitors
    :platform: Unix
    :synopsis: Monitors are a grouping of a watcher and it's associated auditor

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""
from security_monkey.watchers.iam.iam_role import IAMRole
from security_monkey.watchers.iam.iam_group import IAMGroup
from security_monkey.watchers.iam.iam_ssl import IAMSSL
from security_monkey.watchers.iam.iam_user import IAMUser
from moz_security_monkey.watchers.iam.iam_account import IAMAccount
from security_monkey.watchers.iam.managed_policy import ManagedPolicy
from moz_security_monkey.watchers.cloudtrail import CloudTrail
from moz_security_monkey.watchers.route53 import Route53


from security_monkey.auditors.iam.iam_user import IAMUserAuditor
from security_monkey.auditors.iam.iam_group import IAMGroupAuditor
from security_monkey.auditors.iam.iam_ssl import IAMSSLAuditor
from security_monkey.auditors.iam.iam_role import IAMRoleAuditor
from moz_security_monkey.auditors.iam.iam_account import IAMAccountAuditor
from security_monkey.auditors.iam.managed_policy import ManagedPolicyAuditor

from security_monkey.watchers.sns import SNS
from security_monkey.auditors.sns import SNSAuditor
from security_monkey.watchers.sqs import SQS
from security_monkey.watchers.keypair import Keypair
from security_monkey.watchers.security_group import SecurityGroup
from moz_security_monkey.auditors.security_group import SecurityGroupAuditor
from security_monkey.watchers.rds_security_group import RDSSecurityGroup
from security_monkey.auditors.rds_security_group import RDSSecurityGroupAuditor
from security_monkey.watchers.s3 import S3
from moz_security_monkey.auditors.s3 import S3Auditor
from security_monkey.watchers.elb import ELB
from security_monkey.auditors.elb import ELBAuditor
from security_monkey.watchers.redshift import Redshift
from security_monkey.auditors.redshift import RedshiftAuditor
from security_monkey.watchers.elastic_ip import ElasticIP
from security_monkey.watchers.ses import SES
from security_monkey.auditors.ses import SESAuditor
from security_monkey.watchers.vpc.vpc import VPC
from security_monkey.watchers.vpc.subnet import Subnet
from security_monkey.watchers.vpc.route_table import RouteTable
from moz_security_monkey.auditors.cloudtrail import CloudTrailAuditor
from moz_security_monkey.auditors.route53 import Route53Auditor

from security_monkey.monitors import Monitor

__MONITORS = {
    SecurityGroup.index:
        Monitor(SecurityGroup.index, SecurityGroup, SecurityGroupAuditor),
    S3.index:
        Monitor(S3.index, S3, S3Auditor),
    IAMAccount.index:
        Monitor(IAMAccount.index, IAMAccount, IAMAccountAuditor),
    CloudTrail.index:
        Monitor(CloudTrail.index, CloudTrail, CloudTrailAuditor),
    Route53.index:
        Monitor(Route53.index, Route53, Route53Auditor),
}

__ORIGINAL_MONITORS = {
    SQS.index:
        Monitor(SQS.index, SQS, None),
    ELB.index:
        Monitor(ELB.index, ELB, ELBAuditor),
    IAMSSL.index:
        Monitor(IAMSSL.index, IAMSSL, IAMSSLAuditor),
    RDSSecurityGroup.index:
        Monitor(RDSSecurityGroup.index, RDSSecurityGroup, RDSSecurityGroupAuditor),
    SecurityGroup.index:
        Monitor(SecurityGroup.index, SecurityGroup, SecurityGroupAuditor),
    S3.index:
        Monitor(S3.index, S3, S3Auditor),
    IAMUser.index:
        Monitor(IAMUser.index, IAMUser, IAMUserAuditor),
    IAMRole.index:
        Monitor(IAMRole.index, IAMRole, IAMRoleAuditor),
    IAMGroup.index:
        Monitor(IAMGroup.index, IAMGroup, IAMGroupAuditor),
    Keypair.index:
        Monitor(Keypair.index, Keypair, None),
    SNS.index:
        Monitor(SNS.index, SNS, SNSAuditor),
    Redshift.index:
        Monitor(Redshift.index, Redshift, RedshiftAuditor),
    ElasticIP.index:
        Monitor(ElasticIP.index, ElasticIP, None),
    SES.index:
        Monitor(SES.index, SES, SESAuditor),
    VPC.index:
        Monitor(VPC.index, VPC, None),
    Subnet.index:
        Monitor(Subnet.index, Subnet, None),
    RouteTable.index:
        Monitor(RouteTable.index, RouteTable, None),
    ManagedPolicy.index:
        Monitor(ManagedPolicy.index, ManagedPolicy, ManagedPolicyAuditor)
}


def get_monitor(monitor_name):
    return __MONITORS.get(monitor_name)


def all_monitors():
    return __MONITORS.itervalues()
