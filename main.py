import os
import re
import time
import requests
import CloudFlare
import tldextract
import ipaddress
import sys
from CloudFlare.exceptions import CloudFlareAPIError
import logging
from sys import stdout
import math
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

# IP Version: '4' for IPv4 only, '6' for IPv6 only, or "both" for both IPv4 and IPv6
IP_VERSION = os.environ.get('IP_VERSION', 'both')

# Delay
DELAY = os.environ.get('DELAY', 60)

# Initialize Cloudflare client
cf = CloudFlare.CloudFlare(email=CLOUDFLARE_EMAIL, key=CLOUDFLARE_API_KEY)

# Global Variables
failed_hosts = []

def is_valid_wan_ip(ip, version):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if version == 4:
            return ip_obj.version == 4 and not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_unspecified
        elif version == 6:
            return ip_obj.version == 6 and not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_unspecified
    except ValueError:
        return False
    return False


def get_wan_ip(ip_version):
    """Returns WAN IP for the given IP version or exits the program after X amount of tries"""
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
    """Returns WAN IPs for both IPv4 and IPv6 if IP_VERSION is set to "both", else returns IP for the set version"""
    if IP_VERSION == "both":
        return {4: get_wan_ip(4), 6: get_wan_ip(6)}
    elif IP_VERSION == '4':
        return {4: get_wan_ip(4)}
    elif IP_VERSION == '6':
        return {6: get_wan_ip(6)}
    else:
        raise ValueError("Invalid IP version")


def get_traefik_routers():
    """Returns Traefik http routers from the given API URL"""
    response = requests.get(f"{TRAEFIK_API_URL}/api/http/routers")
    return response.json()


def get_cloudflare_zones(cf, per_page=50):
    """Returns all Cloudflare zones with pagination."""
    zones = []
    current_page = 1

    # Get the initial response to determine the total number of pages
    response = cf.zones.get(params={"per_page": per_page, "page": current_page})
    total_zones = len(response)
    total_pages = math.ceil(total_zones / per_page)

    # Add zones from the initial response
    zones.extend(response)

    # Iterate through the remaining pages
    for current_page in range(2, total_pages + 1):
        response = cf.zones.get(params={"per_page": per_page, "page": current_page})
        zones.extend(response)

    return zones


def get_zone_id(domain):
    """Returns zone ID for the given domain"""
    zones = get_cloudflare_zones(cf, per_page=50)
    return next((zone['id'] for zone in zones if zone['name'] == domain), None)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def update_record(zone_id, record_id, record_type, host, ip, proxied):
    cf.zones.dns_records.put(zone_id, record_id, data={
        'type': record_type,
        'name': host,
        'content': ip,
        'proxied': proxied
    })


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def add_record(zone_id, record_type, host, ip, proxied):
    cf.zones.dns_records.post(zone_id, data={
        'type': record_type,
        'name': host,
        'content': ip,
        'proxied': proxied
    })


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def delete_record(zone_id, record_id):
    cf.zones.dns_records.delete(zone_id, record_id)


def update_cloudflare_records(routers, wan_ips, first_run=False):
    """Updates Cloudflare DNS records for the given http routers and WAN IPs"""
    processed_zones = {}
    processed_hosts = set()  # Keep track of processed rule hosts
    entrypoints_list = [entrypoint.strip() for entrypoint in TRAEFIK_ENTRYPOINTS.split(',')]
    custom_urls = [url.strip() for url in CUSTOM_URLS.split(',') if url.strip()]

    def process_host(host):
        extracted_domain = tldextract.extract(host)
        root_domain = ".".join(extracted_domain[1:])

        if not extracted_domain.suffix:
            return

        if root_domain in processed_zones:
            zone_id, dns_records = processed_zones[root_domain]
        else:
            zone_id = get_zone_id(root_domain)
            if not zone_id:
                logger.warning(f"Zone ID for domain {root_domain} not found")
                return

            dns_records = []
            page_num = 1
            while True:
                page_records = cf.zones.dns_records.get(zone_id, params={'page': page_num})
                if not page_records:
                    break
                dns_records.extend(page_records)
                page_num += 1

            processed_zones[root_domain] = (zone_id, dns_records)

        existing_a_records = {record['name']: record for record in dns_records if record['type'] == 'A'}
        existing_aaaa_records = {record['name']: record for record in dns_records if record['type'] == 'AAAA'}

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

                if record['content'] == ip:
                    if first_run:
                        logger.info(f"{record_type} record for {host} is already updated.")
                    continue

                else:
                    logger.info(f"Updating {record_type} record for {host} - proxied: {record['proxied']}")
                    try:
                        update_record(zone_id, record['id'], record_type, host, ip, record['proxied'])
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
                delete_record(zone_id, record['id'])
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
            host = host_match
            if host not in processed_hosts:
                process_host(host)
                processed_hosts.add(host)

    for custom_url in custom_urls:
        if custom_url not in processed_hosts:
            process_host(custom_url)
            processed_hosts.add(custom_url)


def main():
    """Main loop"""
    logger.info("Saltbox Cloudflare DNS container starting.")

    # Check if all required environment variables are set
    if not all([CLOUDFLARE_API_KEY, CLOUDFLARE_EMAIL, TRAEFIK_API_URL, IP_VERSION]):
        logger.error(
            "Please set the required environment variables: CLOUDFLARE_API_KEY, CLOUDFLARE_EMAIL, TRAEFIK_API_URL, "
            "IP_VERSION")
        return

    # Validate Cloudflare global API key
    try:
        get_cloudflare_zones(cf, per_page=5)
    except CloudFlareAPIError as e:
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

            for host in prev_failed_hosts:
                if host in failed_hosts:
                    logger.info(f"Host {host} failed again.")
                else:
                    logger.info(f"Host {host} succeeded on retry.")

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
