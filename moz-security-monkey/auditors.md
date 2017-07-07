# Auditors

## iam_account : check_no_root_mfa

AWS root user has no MFA device configured.
* likelihood_indicator : HIGH
  * An AWS account root user, unprotected by MFA, would get compromised at the
  same rate as any user account where it would be subject to password re-use,
  client malware, weak password guessing, etc.
* http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html#enable-virt-mfa-for-root
* https://wiki.mozilla.org/Security/Fundamentals#mfa

## cloudtrail : check_cloudtrail_exists

CloudTrail doesn't exist
* likelihood_indicator : MEDIUM
  * The absence of CloudTrail logs affect how fast and achievable recovery is
  after a security incident, not whether or not a security incident will occur.

## cloudtrail : check_cloudtrail_is_logging

CloudTrail logging is disabled.
* likelihood_indicator : MEDIUM
  * The absence of CloudTrail logs affect how fast and achievable recovery is
  after a security incident, not whether or not a security incident will occur.

## route53 : check_domain_is_bound

Route53 DNS record is vulnerable to hostile takeover.
* likelihood_indicator : HIGH
  * An attacker need only discover that a DNS name exists to discover the
  domain takeover vulnerability.

## s3 : check_policy inspect_policy_allow_all

POLICY - This Policy Allows Access From Anyone.
* likelihood_indicator : HIGH
  * An attacker need only discover that the S3 bucket exists

## s3 : check_policy inspect_policy_cross_account

POLICY - Friendly Account Access.
* likelihood_indicator : LOW
  * Granting one of our AWS accounts access to the S3 bucket of another account
  means that a compromise in that other account can put this bucket at risk

POLICY - Friendly Third Party Account Access.
* likelihood_indicator : LOW 
  * Granting a known third-party AWS account access to the S3 bucket of one of
  our accounts means that a compromise in that third-party can put this bucket
  at risk. This assumes that since it is a known third party account, it has
  gone through a vendor review

POLICY - Unknown Cross Account Access.
* likelihood_indicator : MEDIUM
  * Granting an AWS account which is neither one of our accounts or a known
  third-party, access to the S3 bucket of one of our accounts means that a
  compromise in that unknown account can put this bucket at risk. We can't
  know the security posture of this other AWS account

## s3 : check_policy inspect_policy_conditionals

POLICY - This policy has conditions.
* likelihood_indicator : LOW
  * Policy conditions are complex and at risk of containing mistakes

## security_group : check_securitygroup_large_port_range

Port Range > 2500 Ports
* likelihood_indicator : MEDIUM
  * Open ports can unintentionally reveal services and those services could
  have vulnerabilities

Port Range > 750 Ports
* likelihood_indicator : MEDIUM
  * Open ports can unintentionally reveal services and those services could
  have vulnerabilities

Port Range > 250 Ports
* likelihood_indicator : MEDIUM
  * Open ports can unintentionally reveal services and those services could
  have vulnerabilities
