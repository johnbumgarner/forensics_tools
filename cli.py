#!/usr/bin/env python3

"""
This Python script provides a command-line interface (CLI) for various forensics operations.
It allows users to perform different types of lookups and queries related to network forensics.

Available commands:
- 'arin': Perform an ARIN WHOIS lookup for the given IP address(es).
- 'abuse': Perform an AbuseIPDB database lookup for the given IP address using an API key.
- 'geo': Perform an IP Geolocation lookup for the given IP address.
- 'mac': Perform a MAC address lookup for the given MAC address.

"""
__author__ = 'John Bumgarner'
__date__ = 'July 23, 2024'
__status__ = 'Production'
__license__ = 'GPL-3'
__copyright__ = "Copyright (C) 2024 John Bumgarner"

##################################################################################
# Date Completed: July 23, 2024
# Author: John Bumgarner
#
# Date Last Revised:
# Revised by:
##################################################################################

##################################################################################
# “AS-IS” Clause
#
# Except as represented in this agreement, all work produced by Developer is
# provided “AS IS”. Other than as provided in this agreement, Developer makes no
# other warranties, express or implied, and hereby disclaims all implied warranties,
# including any warranty of merchantability and warranty of fitness for a particular
# purpose.
##################################################################################

##################################################################################
# Python imports required for basic operations
##################################################################################
# Standard library imports
import sys
import argparse
# Local or project-specific imports
from arin_whois_lookup import ArinWhois
from ip_reputation_lookup import IPReputation
from ip_geolocation_lookup import IPGeoLocation
from mac_address_vendor_lookup import MacAddressLookup


def run_arin_whois(ip_address: str) -> None:
    """
    Run the ARIN WHOIS lookup for a given IP address.

    This function creates an instance of the ArinWhois class and queries the WHOIS
    database for information related to the specified IP address. The result is then printed.

    :param ip_address: The IP address to lookup in the ARIN WHOIS database.
    :param type ip_address: str
    """
    whois = ArinWhois(ip_address)
    result = whois.query_whois()
    print(result)


def run_ip_reputation(ip_address: str, api_key: str) -> None:
    """
    Run the IP reputation lookup for a given IP address using an API key.

    This function creates an instance of the IPReputation class and queries the AbuseIPDB
    database for reputation information related to the specified IP address. The result is then printed.

    :param ip_address: The IP address to lookup in the IP reputation database.
    :param type ip_address: str
    :param api_key: The API key for accessing the IP reputation database.
    :param type api_key: str
    """
    reputation = IPReputation(ip_address, api_key)
    result = reputation.query_abuse_database()
    print(result)


def run_ip_geolocation(ip_address: str) -> None:
    """
    Run the IP geolocation lookup for a given IP address.

    This function creates an instance of the IPGeoLocation class and queries the geolocation
    database for information related to the specified IP address. The result is then printed.

    :param ip_address: The IP address to lookup in the geolocation database.
    :param type ip_address: str
    """
    geo = IPGeoLocation(ip_address)
    result = geo.query_geolocation_database()
    print(result)


def run_mac_address_lookup(mac_address: str) -> None:
    """
    Run the MAC address lookup for a given MAC address.

    This function creates an instance of the MacAddressLookup class and queries the database
    for information related to the specified MAC address. The result is then printed.

    :param mac_address: The MAC address to lookup in the MAC address database.
    :param type mac_address: str
    """
    mac = MacAddressLookup(mac_address)
    result = mac.lookup_address_information()
    print(result)

def main():
    """
    Main function for the Network Forensics Tools CLI.

    This function sets up the command-line interface (CLI) for various forensics tools. It uses the argparse
    library to parse command-line arguments and subcommands for different forensics operations.

    The available commands are:
        - 'arin': Perform an ARIN WHOIS lookup for the given IP address(es).
        - 'abuse': Perform an AbuseIPDB database lookup for the given IP address(es) using an API key.
        - 'geo': Perform an IP Geolocation lookup for the given IP address(es).
        - 'mac': Perform a MAC address lookup for the given MAC address(es).

    Each subcommand has its own set of arguments:
        - ARIN WHOIS lookup:
          - ip_address: IP address or list of IP addresses to lookup.
        - AbuseIPDB database lookup:
          - ip_address: IP address to lookup.
          - api_key: API key for AbuseIPDB.
        - IP Geolocation lookup:
          - ip_address: IP address to lookup.
        - MAC address lookup:
          - mac_address: MAC address to lookup.

    The function then executes the appropriate function based on the provided command and arguments.
    """
    parser = argparse.ArgumentParser(description="Network Forensics Tools CLI")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # ARIN WHOIS lookup
    arin_parser = subparsers.add_parser(name='arin', help='ARIN WHOIS lookup')
    arin_parser.add_argument('ip_address', type=str, nargs='+', help='IP address or list of IP addresses to lookup')

    # AbuseIPDB datebase lookup
    abuse_parser = subparsers.add_parser(name='abuse', help='AbuseIPDB database lookup')
    abuse_parser.add_argument('ip_address', type=str, help='IP address to lookup')
    abuse_parser.add_argument('api_key', type=str, help='API key for AbuseIPDB')

    # IP Geolocation lookup
    geo_parser = subparsers.add_parser(name='geo', help='IP Geolocation lookup')
    geo_parser.add_argument('ip_address', type=str, help='IP address to lookup')

    # MAC (Media Access Control) address lookup
    mac_parser = subparsers.add_parser(name='mac', help='MAC address lookup')
    mac_parser.add_argument('mac_address', type=str, help='MAC address to lookup')

    args = parser.parse_args()

    if args.command == 'arin':
        run_arin_whois(args.ip_address)
    elif args.command == 'abuse':
        run_ip_reputation(args.ip_address, args.api_key)
        print(args.api_key)
    elif args.command == 'geo':
        run_ip_geolocation(args.ip_address)
    elif args.command == 'mac':
        run_mac_address_lookup(args.mac_address)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
