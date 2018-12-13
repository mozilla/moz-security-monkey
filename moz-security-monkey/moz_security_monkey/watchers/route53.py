"""
.. module: security_monkey.watchers.route53
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Gene Wood <gene_wood@cementhorizon.com> @gene1wood

"""

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.exceptions import BotoConnectionIssue
from security_monkey import app

# heroku  there is no app configured at that hostname
# aws NoSuchBucket
# squarespace No Such Account
# github  here isn't a GitHub Pages site here
# shopify Sorry, this shop is currently unavailable
# tumblr  There's nothing here.
# wpengine    The site you were looking for couldn't be found
# desk
# teamwork
# unbounce
# helpjuice
# helpscout
# pingdom
# tictail
# campaignmonitor
# cargocollective
# statuspageio
#
# https://github.com/nahamsec/HostileSubBruteforcer/blob/master/PerlHostileSubBruteforcer/HostileBruteForceScanner.pl
# https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/
# https://github.com/antichown/subdomain-takeover/blob/f7bf89d1cff0e2231e81085a0a0b62849b13ee0d/takeover.py#L73-L131


class Route53(Watcher):
    index = 'route53'
    i_am_singular = 'Route53 record'
    i_am_plural = 'Route53 records'
    third_party_services = {
        'heroku': {
            'domains': [
                '.herokuapp.com',
                '.herokussl.com'
            ],
            'indicators': [
                'there is no app configured at that hostname'
            ],
            'sources': [
                'https://devcenter.heroku.com/articles/custom-domains#configuring-dns-for-subdomains'
            ]
        }
    }

    third_party_domains = [item for sublist
                           in [third_party_services[x]['domains']
                               for x in third_party_services.keys()]
                           for item in sublist]

    def __init__(self, accounts=None, debug=False):
        super(Route53, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):
        """
        :returns: item_list - list of Route53 records.
        :returns: exception_map - A dict where the keys are a tuple containing the
            location of the exception and the value is the actual exception

        """
        self.prep_for_slurp()

        item_list = []
        exception_map = {}
        from security_monkey.common.sts_connect import connect
        for account in self.accounts:
            app.logger.debug("Checking {}/{}".format(self.index, account))

            try:
                route53conn = connect(account, 'route53')

                # Note : This fails if you have over 100 hosted zones
                # maybe create paged_wrap_aws_rate_limited_call
                route53_response = self.wrap_aws_rate_limited_call(
                    route53conn.get_all_hosted_zones
                )
                zones = route53_response['ListHostedZonesResponse']['HostedZones']
                for zone in zones:
                    zone_id = zone['Id'][12:]  # Trim leading '/hostedzone'
                    record_sets = self.wrap_aws_rate_limited_call(
                        route53conn.get_all_rrsets,
                        hosted_zone_id=zone_id
                    )
                    for record in record_sets:
                        if (record.type == 'CNAME'
                            and any([x.endswith(
                                tuple(self.third_party_domains))
                                     for x in record.resource_records])):
                            # This CNAME contains a record which points to a
                            # third party domain
                            item = Route53Item(
                                account=account,
                                name=record.name,
                                config=record)
                            item_list.append(item)

            except Exception as e:
                exc = BotoConnectionIssue(str(e), self.index, account, None)
                self.slurp_exception((self.index, account, 'universal'), exc, exception_map)
                continue

            app.logger.debug(
                "Found {} {}".format(len(item_list), self.i_am_plural))

        return item_list, exception_map


class Route53Item(ChangeItem):
    def __init__(self, region=None, account=None, name=None, config={}):
        super(Route53Item, self).__init__(
            index=Route53.index,
            region='universal',
            account=account,
            name=name,
            new_config=config)
