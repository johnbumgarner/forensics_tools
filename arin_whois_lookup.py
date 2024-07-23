#!/usr/bin/env python3

"""
This Python script is designed to query the American Registry for Internet Numbers(ARIN)
Whois datebase for information related to the registration data associated with either
an IPv4 or IPv6 address.
"""
__author__ = 'John Bumgarner'
__date__ = 'February 29, 2024'
__status__ = 'Production'
__license__ = 'GPL-3'
__copyright__ = "Copyright (C) 2024 John Bumgarner"

##################################################################################
# Date Completed: February 29, 2024
# Author: John Bumgarner
#
# Date Last Revised: July 22, 2024
# Revised by: John Bumgarner
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
##################################################################################
# Python imports required for basic operations
##################################################################################
# Standard library imports
from time import sleep
from typing import Union
from random import randint
# Third-party imports
import requests
# Local or project-specific imports
from utilities.colorized_text import colorized_text


class ArinWhois:
    """
    Purpose
    ----------

    This Python class is used to query the American Registry for Internet Numbers(ARIN) Whois
    datebase for information related to the registration data associated with either a IPv4 or IPv6
    address.

    Usage Examples
    ----------

    # IPv4 example str
    ArinWhois('67.21.32.233').query_whois()

    # IPv4 example list
    ip_addresses = ['67.21.32.233', '67.21.32.230']
    ArinWhois(ip_addresses).query_whois()

    # IPv6 example str
    ArinWhois('2600:1700:6c15:4050:83f:c3a:4dd8:f3ad').query_whois()

    # IPv6 example list
    ip_addresses = ['2600:1700:6c15:4050:83f:c3a:4dd8:f3ad','2600:1700:6c15:4050:83f:c3a:4dd8:f3ad']
    ArinWhois(ip_addresses).query_whois()

    # Combined example
    ip_addresses = ['67.21.32.233','2600:1700:6c15:4050:83f:c3a:4dd8:f3ad']
    ArinWhois(ip_addresses).query_whois()

    Parameters
    ----------
    :param lookup_value: Input data containing the IP addresses to obtain information for
    """

    def __init__(self,
                 lookup_value: str | list = ''):
        self.lookup_value = lookup_value

    data: dict = {}

    @classmethod
    def _get_whois_json(cls, ip_address: str) -> Union[dict, None]:
        """
        Obtains the WHOIS information for the specific IP address being queried.

        :param ip_address: IP address being queried
        :return: dictionary of WHOIS data
        :rtype: dict
        """
        sleep(randint(a=1, b=3))
        try:
            response = requests.get(url=f'https://whois.arin.net/rest/ip/{ip_address}.json', timeout=(5, 10))
            if response.status_code == 200:
                cls.data = response.json()
                return cls.data
        except requests.exceptions.Timeout:
            colorized_text(text=f"Request timed out for IP address {ip_address}", color='red')
        except requests.exceptions.RequestException as e:
            colorized_text(text=f"An error occurred: {e}", color='red')
        return None

    @classmethod
    def _get_registered_organization(cls) -> Union[str, None]:
        """
        Obtains the name of the registered organization associated with the
        specific IP address being queried.

        :return: registered organization name
        :rtype: str
        """
        try:
            if not cls.data['net']['orgRef']['@name']:
                return "registered organization unavailable"
            elif cls.data['net']['orgRef']['@name']:
                return cls.data['net']['orgRef']['@name']
        except KeyError:
            colorized_text(text="Registered_organization is not present in JSON data", color='red')
        return None

    @classmethod
    def _get_network_range(cls) -> Union[str, None]:
        """
        Obtains the IP address range associated with the specific IP address
        being queried.

        :return: IP address range
        :rtype: str
        """
        try:
            if not cls.data['net']['netBlocks']['netBlock']['startAddress']['$']:
                return "netblock range unavailable"
            elif cls.data['net']['netBlocks']['netBlock']['startAddress']['$']:
                starting_ip_address = cls.data['net']['netBlocks']['netBlock']['startAddress']['$']
                ending_ip_address = cls.data['net']['netBlocks']['netBlock']['endAddress']['$']
                return f'{starting_ip_address}-{ending_ip_address}'
        except KeyError:
            colorized_text(text='The JSON keys to obtain the network range were invalid.', color='red')
        return None

    @classmethod
    def _get_cidr_range(cls) -> Union[str, None]:
        """
        Obtains the Classless Inter-Domain Routing (CIDR) range associated with the
        specific IP address being queried.

        :return: CIDR range
        :rtype: str
        """
        try:
            if not cls.data['net']['netBlocks']['netBlock']['startAddress']['$']:
                return "CIDR range unavailable"
            elif cls.data['net']['netBlocks']['netBlock']['startAddress']['$']:
                starting_ip_address = cls.data['net']['netBlocks']['netBlock']['startAddress']['$']
                cidr_subnet_range = cls.data['net']['netBlocks']['netBlock']['cidrLength']['$']
                return f'{starting_ip_address}/{cidr_subnet_range}'
        except KeyError:
            colorized_text(text='The JSON keys to obtain the CIDR range were invalid.', color='red')
        return None

    def query_whois(self) -> Union[dict | list[dict] | None]:
        """
        Processes the input data, which could be a single IP address
        or a list of IP address.  An IP address is queried against
        the ARIN WHOIS database.

        :return: dict of data elements related to the input data
        :rtype: dict or list
        """
        if isinstance(self.lookup_value, str):
            ArinWhois._get_whois_json(self.lookup_value)
            registered_organization = ArinWhois._get_registered_organization()
            network_range = ArinWhois._get_network_range()
            cidr_range = ArinWhois._get_cidr_range()
            data_elements = {'ip_address': self.lookup_value,
                             'organization': registered_organization,
                             'network': network_range,
                             'cidr': cidr_range}
            return data_elements
        elif isinstance(self.lookup_value, list):
            data_elements = []
            for item in self.lookup_value:
                ArinWhois._get_whois_json(item)
                registered_organization = ArinWhois._get_registered_organization()
                network_range = ArinWhois._get_network_range()
                cidr_range = ArinWhois._get_cidr_range()
                data = {'ip_address': item,
                        'organization': registered_organization,
                        'network': network_range,
                        'cidr': cidr_range}
                data_elements.append(data)
            return data_elements
        return None
