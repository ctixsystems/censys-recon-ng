mkdir -p ~/.recon-ng/modules/recon/companies-contacts
cp censys_email_address.py ~/.recon-ng/modules/recon/companies-contacts

mkdir -p ~/.recon-ng/modules/recon/companies-domains
cp censys_subdomains.py ~/.recon-ng/modules/recon/companies-domains

mkdir -p ~/.recon-ng/modules/recon/companies-hosts
cp censys_org.py ~/.recon-ng/modules/recon/companies-hosts
cp censys_tls_subjects.py ~/.recon-ng/modules/recon/companies-hosts
cp censys_tls_issuers.py ~/.recon-ng/modules/recon/companies-hosts

mkdir -p ~/.recon-ng/modules/recon/companies-netblocks
cp censys_company_netname.py ~/.recon-ng/modules/recon/companies-netblocks

mkdir -p ~/.recon-ng/modules/recon/domains-companies
cp censys_companies.py ~/.recon-ng/modules/recon/domains-companies

mkdir -p ~/.recon-ng/modules/recon/domains-hosts
cp censys_domain.py ~/.recon-ng/modules/recon/domains-hosts

mkdir -p ~/.recon-ng/modules/recon/hosts-hosts
cp censys_query.py ~/.recon-ng/modules/recon/hosts-hosts

mkdir -p ~/.recon-ng/modules/recon/hosts-ports
cp censys_hostname.py ~/.recon-ng/modules/recon/hosts-ports
cp censys_ip.py ~/.recon-ng/modules/recon/hosts-ports

mkdir -p ~/.recon-ng/modules/recon/netblocks-companies
cp censys_netblock_company.py ~/.recon-ng/modules/recon/netblocks-companies

mkdir -p ~/.recon-ng/modules/recon/netblocks-hosts
cp censys_netblock.py ~/.recon-ng/modules/recon/netblocks-hosts

for key in censysio_id censysio_secret; do
	echo "INSERT INTO keys (name) VALUES (\"$key\");" | sqlite3 ~/.recon-ng/keys.db
done
