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
CLOUDFLARE_PROXY_DEFAULT = os.environ.get('CLOUDFLARE_PROXY_DEFAULT', False)

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


def is_valid_wan_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_unspecified
    except ValueError:
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
                if is_valid_wan_ip(ip_address):
                    return ip_address
            except (requests.RequestException, ValueError):
                continue

        if attempts < max_tries:
            logger.warning(f"Failed to obtain a valid WAN IPv{ip_version} address. Retrying in {delay_between_attempts} seconds.")
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


def get_cloudflare_zones():
    """Returns all Cloudflare zones"""
    return cf.zones.get()


def get_zone_id(domain):
    """Returns zone ID for the given domain"""
    zones = get_cloudflare_zones()
    return next((zone['id'] for zone in zones if zone['name'] == domain), None)


def update_cloudflare_records(routers, wan_ips):
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
                if record['content'] != ip:
                    logger.info(f"Updating {record_type} record for {host}")
                    cf.zones.dns_records.put(zone_id, record['id'], data={
                        'type': record_type,
                        'name': host,
                        'content': ip,
                        'proxied': record['proxied']
                    })
            else:
                logger.info(f"Adding {record_type} record for {host}")
                cf.zones.dns_records.post(zone_id, data={
                    'type': record_type,
                    'name': host,
                    'content': ip,
                    'proxied': bool(CLOUDFLARE_PROXY_DEFAULT)
                })

    for router in routers.values():
        # Check if router is using one of the given entrypoints
        if router.get('entryPoints') and all(
                entrypoint not in router['entryPoints']
                for entrypoint in entrypoints_list
        ):
            continue

        rule = router.get('rule', '')
        host_match = re.search(r"Host\(`(.*?)`\)", rule)
        if not host_match:
            continue

        host = host_match[1]
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
        get_cloudflare_zones()
    except CloudFlareAPIError as e:
        if 'unknown x-auth-key or x-auth-email' not in str(e).lower():
            raise

        logger.error("Invalid Cloudflare global API key or email")
        return

    # Initialize variables
    first_run = True
    last_wan_ips = {}
    routers = {router['name']: router for router in get_traefik_routers()}

    while True:
        try:
            new_routers = {router['name']: router for router in get_traefik_routers()}
            new_wan_ips = get_wan_ips()
            if new_wan_ips != last_wan_ips:
                logger.info(f"WAN IPs changed to {new_wan_ips}")
                last_wan_ips = new_wan_ips
                update_cloudflare_records(new_routers, last_wan_ips)
            added_routers = {k: v for k, v in new_routers.items() if k not in routers}
            routers = new_routers
            if added_routers:
                update_cloudflare_records(added_routers, new_wan_ips)
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
