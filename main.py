import os
import re
import time
import requests
import cloudflare
import tldextract
import ipaddress
import sys
import logging
from sys import stdout
from tenacity import retry, stop_after_attempt, wait_exponential, RetryError

# Define logger
logger = logging.getLogger('mylogger')

logger.setLevel(logging.DEBUG)
logFormatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")
consoleHandler = logging.StreamHandler(stdout)
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

# Your Cloudflare global API key and email
CLOUDFLARE_API_KEY = os.environ.get('CLOUDFLARE_API_KEY')
CLOUDFLARE_EMAIL = os.environ.get('CLOUDFLARE_EMAIL')
CLOUDFLARE_PROXY_DEFAULT = os.environ.get('CLOUDFLARE_PROXY_DEFAULT', "False").lower() in ('true', '1', 't')

# Traefik API URL
TRAEFIK_API_URL = os.environ.get('TRAEFIK_API_URL')
TRAEFIK_ENTRYPOINTS = os.environ.get('TRAEFIK_ENTRYPOINTS')

CUSTOM_URLS = os.environ.get('CUSTOM_URLS', '')

# IP Version: '4' for IPv4 only, '6' for IPv6 only, or "both" for IPv4 and IPv6
IP_VERSION = os.environ.get('IP_VERSION', 'both')

# Delay
DELAY = os.environ.get('DELAY', 60)

# Initialize Cloudflare client
cf = cloudflare.Cloudflare(api_email=CLOUDFLARE_EMAIL, api_key=CLOUDFLARE_API_KEY)

# Global Variables
failed_hosts = []


def is_valid_wan_ip(ip, version):
    """
    Check if the provided IP address is a valid WAN IP address.

    Args:
        ip (str): The IP address to validate.
        version (int): The IP version to validate against (4 for IPv4, 6 for IPv6).

    Returns:
        bool: True if the IP is a valid WAN IP address, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if version == 4:
            return (ip_obj.version == 4 and
                    not ip_obj.is_private and
                    not ip_obj.is_loopback and
                    not ip_obj.is_unspecified)
        elif version == 6:
            return (ip_obj.version == 6 and
                    not ip_obj.is_private and
                    not ip_obj.is_loopback and
                    not ip_obj.is_unspecified)
    except ValueError:
        return False
    return False


def get_wan_ip(ip_version):
    """
    Retrieve a valid WAN IP address of the specified version using multiple services.

    Args:
        ip_version (int): The IP version to retrieve (4 for IPv4, 6 for IPv6).

    Returns:
        str: The valid WAN IP address of the specified version.

    Raises:
        SystemExit: If a valid WAN IP address cannot be obtained after multiple attempts.
    """
    ip_services = [
        f"https://ipify{'6' if ip_version == 6 else ''}.saltbox.dev?format=json",
        f"https://api{'6' if ip_version == 6 else '4'}.ipify.org?format=json",
        f"https://{'ipv6' if ip_version == 6 else 'ipv4'}.icanhazip.com"
    ]

    max_tries = 3
    delay_between_attempts = 5
    for attempts in range(1, max_tries + 1):
        for service_url in ip_services:
            try:
                response = requests.get(service_url, timeout=5)
                response.raise_for_status()

                ip_address = (
                    response.json()["ip"]
                    if 'json' in service_url
                    else response.text.strip()
                )
                if is_valid_wan_ip(ip_address, ip_version):
                    return ip_address
                else:
                    continue
            except (requests.RequestException, ValueError):
                continue

        if attempts < max_tries:
            logger.warning(
                f"Failed to obtain a valid WAN IPv{ip_version} address. Retrying in {delay_between_attempts} seconds.")
            time.sleep(delay_between_attempts)

    logger.error(f"Failed to obtain a valid WAN IPv{ip_version} address after {max_tries} tries")
    sys.exit(1)


def get_wan_ips():
    """
    Retrieve WAN IP addresses for the specified IP version(s).

    Returns:
        dict: A dictionary containing the WAN IP address(es) for the specified IP version(s).

    Raises:
        ValueError: If an invalid IP version is provided.
    """
    if IP_VERSION == "both":
        return {4: get_wan_ip(4), 6: get_wan_ip(6)}
    elif IP_VERSION == '4':
        return {4: get_wan_ip(4)}
    elif IP_VERSION == '6':
        return {6: get_wan_ip(6)}
    else:
        raise ValueError("Invalid IP version")


def get_traefik_routers():
    """
    Retrieve the complete list of Traefik routers from the specified API URL with pagination support.
    By default, returns up to 100 results per page.

    Returns:
        list[dict]: A list of Traefik router dictionaries.
    """
    all_routers = []
    current_page = 1
    per_page = 100
    has_more_pages = True

    while has_more_pages:
        try:
            response = requests.get(
                f"{TRAEFIK_API_URL}/api/http/routers",
                params={'page': current_page, 'per_page': per_page}
            )
            response.raise_for_status()

            # Check if we got any routers
            if not (page_routers := response.json()):
                has_more_pages = False
                continue

            # Add page results to our list
            all_routers.extend(page_routers)

            # Check next page - defaults to current page if header is missing
            next_page = int(response.headers.get('X-Next-Page', current_page))

            # Stop if we're not getting a new page number
            if next_page <= current_page:
                has_more_pages = False
            else:
                current_page = next_page

        except requests.RequestException as e:
            logger.error(f"Error fetching Traefik routers page {current_page}: {e}")
            has_more_pages = False

    return all_routers


def get_cloudflare_zones(cf_client):
    """
    Retrieve a list of Cloudflare zones using the provided Cloudflare client.

    Args:
        cf_client: The Cloudflare client object.

    Returns:
        list: A list of Cloudflare zones.
    """
    return cf_client.zones.list()


def get_zone_id(domain):
    """
    Retrieve the Cloudflare zone ID for the specified domain.

    Args:
        domain (str): The domain name to get the zone ID for.

    Returns:
        str: The Cloudflare zone ID for the domain, or None if not found.
    """
    return next((zone.id for zone in get_cloudflare_zones(cf) if zone.name == domain), None)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def update_record(zone_id, record_id, record_type, host, ip, proxied):
    """
    Update a DNS record in the specified Cloudflare zone.

    Args:
        zone_id (str): The ID of the Cloudflare zone.
        record_id (str): The ID of the DNS record to update.
        record_type (str): The type of DNS record to update ('A' or 'AAAA').
        host (str): The hostname for the DNS record.
        ip (str): The new IP address associated with the DNS record.
        proxied (bool): Whether the DNS record is proxied through Cloudflare.
    """
    try:
        # Call update with explicit type parameter based on record_type
        kwargs = {
            'zone_id': zone_id,
            'dns_record_id': record_id,
            'name': host,
            'content': ip,
            'proxied': proxied
        }

        if record_type == 'A':
            kwargs['type'] = 'A'
            cf.dns.records.update(**kwargs)
        elif record_type == 'AAAA':
            kwargs['type'] = 'AAAA'
            cf.dns.records.update(**kwargs)
        elif record_type == 'CNAME':
            kwargs['type'] = 'CNAME'
            cf.dns.records.update(**kwargs)
        elif record_type == 'TXT':
            kwargs['type'] = 'TXT'
            cf.dns.records.update(**kwargs)
        elif record_type == 'MX':
            kwargs['type'] = 'MX'
            cf.dns.records.update(**kwargs)
        elif record_type == 'NS':
            kwargs['type'] = 'NS'
            cf.dns.records.update(**kwargs)
        elif record_type == 'PTR':
            kwargs['type'] = 'PTR'
            cf.dns.records.update(**kwargs)
        else:
            logger.error(f"Unsupported record type: {record_type}")
            raise ValueError(f"Unsupported record type: {record_type}")
    except Exception as e:
        logger.error(f"Error updating record: {e}")
        raise


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def add_record(zone_id, record_type, host, ip, proxied):
    """
    Add a DNS record to the specified Cloudflare zone.

    Args:
        zone_id (str): The ID of the Cloudflare zone.
        record_type (str): The type of DNS record to add.
        host (str): The hostname for the DNS record.
        ip (str): The IP address associated with the DNS record.
        proxied (bool): Whether the DNS record is proxied through Cloudflare.
    """
    try:
        kwargs = {
            'zone_id': zone_id,
            'name': host,
            'content': ip,
            'proxied': proxied
        }

        if record_type == 'A':
            kwargs['type'] = 'A'
            cf.dns.records.create(**kwargs)
        elif record_type == 'AAAA':
            kwargs['type'] = 'AAAA'
            cf.dns.records.create(**kwargs)
        elif record_type == 'CNAME':
            kwargs['type'] = 'CNAME'
            cf.dns.records.create(**kwargs)
        elif record_type == 'TXT':
            kwargs['type'] = 'TXT'
            cf.dns.records.create(**kwargs)
        elif record_type == 'MX':
            kwargs['type'] = 'MX'
            cf.dns.records.create(**kwargs)
        elif record_type == 'NS':
            kwargs['type'] = 'NS'
            cf.dns.records.create(**kwargs)
        elif record_type == 'PTR':
            kwargs['type'] = 'PTR'
            cf.dns.records.create(**kwargs)
        else:
            logger.error(f"Unsupported record type: {record_type}")
            raise ValueError(f"Unsupported record type: {record_type}")
    except Exception as e:
        logger.error(f"Error adding record: {e}")
        raise


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def delete_record(zone_id, record_id):
    """
    Delete a DNS record from the specified Cloudflare zone.

    Args:
        zone_id (str): The ID of the Cloudflare zone.
        record_id (str): The ID of the DNS record to delete.
    """
    try:
        cf.dns.records.delete(zone_id=zone_id, dns_record_id=record_id)
    except Exception as e:
        logger.error(f"Error deleting record: {e}")
        raise


def update_cloudflare_records(routers, wan_ips, first_run=False):
    """
    Update Cloudflare DNS records based on the provided routers and WAN IP addresses.

    Args:
        routers (dict): A dictionary of routers.
        wan_ips (dict): A dictionary of WAN IP addresses.
        first_run (bool, optional): Flag indicating if it's the first run. Defaults to False.
    """
    processed_zones = {}
    processed_hosts = set()  # Keep track of processed rule hosts
    entrypoints_list = [entrypoint.strip() for entrypoint in TRAEFIK_ENTRYPOINTS.split(',')]
    custom_urls = [url.strip() for url in CUSTOM_URLS.split(',') if url.strip()]

    def process_host(host):
        host = host.lower()
        extracted_domain = tldextract.extract(host)
        root_domain = extracted_domain.top_domain_under_public_suffix

        if not extracted_domain.suffix:
            return

        if root_domain in processed_zones:
            zone_id, dns_records = processed_zones[root_domain]
        else:
            zone_id = get_zone_id(root_domain)
            if not zone_id:
                logger.warning(f"Zone ID for domain {root_domain} not found")
                return

            logger.debug(f"Zone ID for domain {root_domain} is {zone_id}")

            dns_records = []
            for dns_record in cf.dns.records.list(zone_id=zone_id):
                dns_records.append(dns_record)

            processed_zones[root_domain] = (zone_id, dns_records)

        existing_a_records = {record.name: record for record in dns_records if record.type == 'A'}
        existing_aaaa_records = {record.name: record for record in dns_records if record.type == 'AAAA'}
        existing_cname_records = {record.name: record for record in dns_records if record.type == 'CNAME'}

        # Check for CNAME and do cleanup if needed
        if host in existing_cname_records:
            cname_record = existing_cname_records[host]
            logger.info(f"Found CNAME record for {host}.")
            try:
                delete_record(zone_id, cname_record.id)
                logger.info(f"Deleted CNAME record for {host}")
            except RetryError:
                failed_hosts.append(host)
                return

        for ip_version, ip in wan_ips.items():
            if ip_version == 4:
                record_type = 'A'
                existing_records = existing_a_records
            elif ip_version == 6:
                record_type = 'AAAA'
                existing_records = existing_aaaa_records
            else:
                logger.error(f"Invalid IP version: {ip_version}")
                continue

            if host in existing_records:
                record = existing_records[host]

                if record.content == ip:
                    if first_run:
                        logger.debug(f"{record_type} record for {host} is already updated.")
                    continue

                else:
                    logger.info(f"Updating {record_type} record for {host} - proxied: {record.proxied}")
                    try:
                        update_record(zone_id, record.id, record_type, host, ip, record.proxied)
                    except RetryError:
                        failed_hosts.append(host)

            else:
                logger.info(f"Adding {record_type} record for {host} - proxied: {CLOUDFLARE_PROXY_DEFAULT}")
                try:
                    add_record(zone_id, record_type, host, ip, CLOUDFLARE_PROXY_DEFAULT)
                except RetryError:
                    failed_hosts.append(host)

        if IP_VERSION != '6' and IP_VERSION != 'both' and host in existing_aaaa_records:
            record = existing_aaaa_records[host]
            logger.info(f"Removing AAAA record for {host} - not using IPv6")
            try:
                delete_record(zone_id, record.id)
            except RetryError:
                failed_hosts.append(host)

    for router in routers.values():
        # Check if router is using one of the given entrypoints
        if router.get('entryPoints') and all(
                entrypoint not in router['entryPoints']
                for entrypoint in entrypoints_list
        ):
            continue

        rule = router.get('rule', '')
        host_matches = re.findall(r"Host\(`(.*?)`\)", rule)
        for host_match in host_matches:
            if host_match not in processed_hosts:
                process_host(host_match)
                processed_hosts.add(host_match)

    for custom_url in custom_urls:
        if custom_url not in processed_hosts:
            process_host(custom_url)
            processed_hosts.add(custom_url)


def main():
    """
    Main function to manage updating Cloudflare DNS records based on Traefik routers and WAN IP changes.
    """
    logger.info("Saltbox Cloudflare DNS container starting.")

    # Check if all required environment variables are set
    if not all([CLOUDFLARE_API_KEY, CLOUDFLARE_EMAIL, TRAEFIK_API_URL, IP_VERSION]):
        logger.error(
            "Please set the required environment variables: CLOUDFLARE_API_KEY, CLOUDFLARE_EMAIL, TRAEFIK_API_URL, "
            "IP_VERSION")
        return

    # Validate Cloudflare global API key
    try:
        get_cloudflare_zones(cf)
    except cloudflare.APIConnectionError as e:
        if 'unknown x-auth-key or x-auth-email' not in str(e).lower():
            raise

        logger.error("Invalid Cloudflare global API key or email")
        return

    # Small delay to ensure Traefik container is running
    time.sleep(10)

    # Initialize variables
    first_run = True
    wan_ips = {}
    routers = {router['name']: router for router in get_traefik_routers()}

    while True:
        try:
            new_routers = {router['name']: router for router in get_traefik_routers()}
            new_wan_ips = get_wan_ips()

            if not first_run:
                logger.debug(f"Previous WAN IPs: {wan_ips} - Current: {new_wan_ips}")

            if new_wan_ips != wan_ips:
                logger.info(f"WAN IPs changed to {new_wan_ips}")
                wan_ips = new_wan_ips

            # Generate a copy of failed_hosts
            prev_failed_hosts = failed_hosts.copy()
            update_cloudflare_records(new_routers, wan_ips, first_run)

            # If any hosts failed previously, try them again
            if prev_failed_hosts:
                logger.info(f"Retrying failed hosts: {prev_failed_hosts}")

            for prev_failed_host in prev_failed_hosts:
                if prev_failed_host in failed_hosts:
                    logger.info(f"Host {prev_failed_host} failed again.")
                else:
                    logger.info(f"Host {prev_failed_host} succeeded on retry.")

            added_routers = {k: v for k, v in new_routers.items() if k not in routers}
            routers = new_routers
            if added_routers:
                update_cloudflare_records(added_routers, wan_ips)

            elif first_run:
                first_run = False
            else:
                logger.info("No new routers found")

        except Exception as e:
            logger.error(f"{e}")

        logger.info(f"Rechecking in {int(DELAY)} seconds.")
        time.sleep(int(DELAY))


if __name__ == "__main__":
    main()
