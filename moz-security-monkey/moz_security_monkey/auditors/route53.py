"""
.. module: security_monkey.auditors.route53
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Gene Wood <gene_wood@cementhorizon.com> @gene1wood

"""
from moz_security_monkey.watchers.route53 import Route53
from security_monkey.auditor import Auditor


class Route53Auditor(Auditor):
    index = Route53.index
    i_am_singular = Route53.i_am_singular
    i_am_plural = Route53.i_am_plural
    third_party_services = Route53.third_party_services

    def __init__(self, accounts=None, debug=False):
        super(Route53Auditor, self).__init__(accounts=accounts, debug=debug)

    def get_service_from_domain(self, name):
        for service in self.third_party_services.keys():
            if name.endswith(
                    tuple(self.third_party_services[service]['domains'])):
                return service
        return False

    def check_domain_is_bound(self, route53_item):
        service = self.get_service_from_domain(route53_item.name)
        if service and False:
            # Fetch a URL constructed from route53_item.name
            # Check against third_party_services[service]['indicators']
            notes = None
            self.add_issue(8, "Route53 DNS record is vulnerable to hostile "
                              "takeover.", route53_item, notes)
