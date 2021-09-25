from recon.core.module import BaseModule

from censys.search import CensysIPv4
from censys.common.exceptions import CensysException


class Module(BaseModule):
    meta = {
        'name': 'Censys hosts by certificate issuers',
        'author': 'ctixsystems',
        'version': '0.9',
        'description': 'Retrieves the TLS certificates for a given issuer. \
            Updates the \'hosts\' and \'ports\' tables with the results.',
        'query': 'SELECT DISTINCT company FROM companies WHERE company IS NOT NULL',
        'dependencies': ['censys'],
        'required_keys': ['censysio_id', 'censysio_secret'],
    }

    def module_run(self, companies):
        api_id = self.get_key('censysio_id')
        api_secret = self.get_key('censysio_secret')
        c = CensysIPv4(api_id, api_secret, timeout=self._global_options['timeout'])
        IPV4_FIELDS = [
            'ip',
            'protocols',
            'location.country',
            'location.latitude',
            'location.longitude',
            'location.province',
            '443.https.tls.certificate.parsed.names',
            '25.smtp.starttls.tls.certificate.parsed.names',
            '110.pop3.starttls.tls.certificate.parsed.names',
        ]

        SEARCH_FIELDS = [
            '443.https.tls.certificate.parsed.issuer.common_name',
            '25.smtp.starttls.tls.certificate.parsed.issuer.common_name',
            '465.smtp.tls.tls.certificate.parsed.issuer.common_name',
            '587.smtp.starttls.tls.certificate.parsed.issuer.common_name',
            '1521.oracle.banner.tls.certificate.parsed.issuer.common_name',
            '3306.mysql.banner.tls.certificate.parsed.issuer.common_name',
            '3389.rdp.banner.tls.certificate.parsed.issuer.common_name',
            '5432.postgres.banner.tls.certificate.parsed.issuer.common_name',
            '8883.mqtt.banner.tls.certificate.parsed.issuer.common_name',
        ]
        for company in companies:
            self.heading(company, level=0)
            try:
                query = ' OR '.join(
                    ['{0}:"{1}"'.format(x, company) for x in SEARCH_FIELDS]
                )
                payload = c.search(query, IPV4_FIELDS)
            except CensysException:
                continue
            for result in payload:
                names = set()
                for k, v in result.items():
                    if k.endswith('.parsed.names'):
                        for name in v:
                            names.add(name)
                if len(names) < 1:
                    # make sure we have at least a blank name
                    names.add('')
                for name in names:
                    if name.startswith('*.'):
                        self.insert_domains(name.replace('*.', ''))
                        continue
                    self.insert_hosts(
                        host=name,
                        ip_address=result['ip'],
                        country=result.get('location.country', ''),
                        region=result.get('location.province', ''),
                        latitude=result.get('location.latitude', ''),
                        longitude=result.get('location.longitude', ''),
                    )

                for protocol in result['protocols']:
                    port, service = protocol.split('/')
                    self.insert_ports(
                        ip_address=result['ip'],
                        host=name,
                        port=port,
                        protocol=service,
                    )
