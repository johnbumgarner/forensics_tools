#!/usr/bin/env python3

"""
This Python script is designed to query the maclookup datebase located at https://api.maclookup.app
for information related to a specific MAC (Media Access Control) address.
"""
__author__ = 'John Bumgarner'
__date__ = 'February 15, 2024'
__status__ = 'Production'
__license__ = 'GPL-3'
__copyright__ = "Copyright (C) 2024 John Bumgarner"

##################################################################################
# Date Completed: February 15, 2024
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
# Standard library imports
import sys
from time import sleep
from typing import Union
from random import randint
# Third-party imports
import requests
# Local or project-specific imports
from utilities.colorized_text import colorized_text


class MacAddressLookup:
    """
    Purpose
    ----------

    This Python class is used to query the maclookup datebase located at https://api.maclookup.app
    for information related to a specific MAC (Media Access Control) address.

    Usage Examples
    ----------

    # String Example
    data = MacAddressLookup('04:7b:cb:3b:75:94').lookup_address_information()
    # do something with the results

    # List Example
    mac_addresses = ['04:7b:cb:3b:75:94', '04:7b:cb:64:94:a5']
    data = MacAddressLookup(mac_addresses).lookup_address_information()
    # do something with the results

    Parameters
    ----------
    :param lookup_value: Input data containing the MAC addresses to obtain information for
    """

    def __init__(self,
                 lookup_value: str | list = ''):
        self.lookup_value = lookup_value

    data: dict = {}

    @classmethod
    def _get_json_data(cls, hardware_id) -> Union[dict, None]:
        sleep(randint(a=1, b=3))
        response = requests.get(url=f'https://api.maclookup.app/v2/macs/{hardware_id}', timeout=(5, 10))
        if response.status_code == 400:
            colorized_text(text="An unknown error has occurred.", color='red')
            sys.exit(1)
        elif response.status_code == 401:
            colorized_text(text="An Unauthorized Request has occurred.", color='red')
            sys.exit(1)
        elif response.status_code == 429:
            colorized_text(text="Too Many Requests with the Rate Limit period.", color='red')
            sys.exit(1)
        elif response.status_code == 200:
            cls.data = response.json()
            return cls.data
        return None

    @classmethod
    def _get_registered_organization(cls) -> Union[str, None]:
        """
        Obtains the name of the registered organization associated with the
        MAC address being queried.

        :return: registered organization name
        :rtype: string
        """
        try:
            if cls.data['isRand'] is True:
                return "randomly assigned"
            elif cls.data['isRand'] is False:
                return cls.data['company']
        except KeyError:
            colorized_text(text="Registered organization is not present in JSON data", color='red')
        return None

    @classmethod
    def _get_registered_organization_address(cls) -> Union[str, None]:
        """
        Obtains the address of the registered organization associated with the
        MAC address being queried.

        :return: address of registered organization
        :rtype: string
        """
        try:
            if not cls.data['address']:
                return "address unavailable"
            elif cls.data['address']:
                return cls.data['address']
        except KeyError:
            colorized_text(text="Registered organization's address is not present in JSON data", color='red')
        return None

    @classmethod
    def _get_registered_organization_country(cls) -> Union[str, None]:
        """
        Obtains the country code for the registered organization associated
        with the MAC address being queried.

        :return: country code of registered organization
        :rtype: string
        """
        try:
            if not cls.data['country']:
                return "country unavailable"
            elif cls.data['country']:
                return cls.data['country']
        except KeyError:
            colorized_text(text="Registered organization's country is not present in JSON data", color='red')
        return None

    def lookup_address_information(self) -> Union[dict | list[dict] | None]:
        """
        Searches the JSON data for specific data elements associated with the
        MAC address being queried.

        :return: registered agent information
        :rtype: tuple
        """
        if isinstance(self.lookup_value, str):
            MacAddressLookup._get_json_data(self.lookup_value)
            registered_organization = MacAddressLookup._get_registered_organization()
            organization_address = MacAddressLookup._get_registered_organization_address()
            country = MacAddressLookup._get_registered_organization_country()
            data_elements = {'mac_address': self.lookup_value,
                             'registered_organization': registered_organization,
                             'organization_address': organization_address,
                             'country': country}
            return data_elements
        elif isinstance(self.lookup_value, list):
            data_elements = []
            for item in self.lookup_value:
                MacAddressLookup._get_json_data(item)
                registered_organization = MacAddressLookup._get_registered_organization()
                organization_address = MacAddressLookup._get_registered_organization_address()
                country = MacAddressLookup._get_registered_organization_country()
                data = {'mac_address': item,
                        'registered_organization': registered_organization,
                        'organization_address': organization_address,
                        'country': country}
                data_elements.append(data)
            return data_elements
        return None
