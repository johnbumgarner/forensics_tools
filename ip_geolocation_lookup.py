#!/usr/bin/env python3

"""
This Python script is designed to query the IP Geolocation database located
at https://ip-api.com for geographical location information related
to an IP address.

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
# Standard library imports
import sys
import json
from time import sleep
from typing import Union
from random import randint
# Third-party imports
import requests
# Local or project-specific imports
from utilities.colorized_text import colorized_text


class IPGeoLocation:
    """
    Purpose
    ----------

    This Python script is designed to query the IP Geolocation database located
    at https://ip-api.com for geographical location information related
    to an IP address.

    Usage Examples
    ----------

    # IPv4 example str
    IPGeoLocation('67.21.32.233').query_geolocation_database()

    # IPv4 example list
    ip_addresses = ['67.21.32.233', '67.21.32.230']
    IPGeoLocation(ip_addresses).query_geolocation_database()

    # IPv6 example str
    IPGeoLocation('2600:1700:6c15:4050:83f:c3a:4dd8:f3ad').query_geolocation_database()

    # IPv6 example list
    ip_addresses = ['2600:1700:6c15:4050:83f:c3a:4dd8:f3ad', '2600:1700:6c15:4050:83f:c3a:4dd8:f3ad']
    IPGeoLocation(ip_addresses).query_geolocation_database()

    # Combined Example
    ip_addresses = ['67.21.32.233', '2600:1700:6c15:4050:83f:c3a:4dd8:f3ad']
    IPGeoLocation(ip_addresses).query_geolocation_database()

    Parameters
    ----------
    :param lookup_value: Input data containing the IP addresses to obtain information for
    """

    def __init__(self,
                 lookup_value: str | list = ''):
        self.lookup_value = lookup_value

    @staticmethod
    def _get_json_data(ip_address: str) -> Union[dict | None]:
        """
        Obtains the reputation information for the IP address being queried.

        :param ip_address: IP address being queried
        :return: dictionary of reputation data
        :rtype: dictionary
        """
        sleep(randint(a=1, b=3))

        try:
            response = requests.request(method='GET', url=f'http://ip-api.com/json/{ip_address}', timeout=(5, 10))
            decoded_response = json.loads(response.text)
            if response.status_code == 200:
                query_status = decoded_response["status"]
                if query_status == 'fail':
                    colorized_text(text=f'The query failed. Please review your input data for {ip_address}',
                                   color='red')
                elif query_status == 'success':
                    return decoded_response
        except requests.ConnectionError:
            colorized_text(text='A ConnectionError has occurred.', color='red')
            sys.exit(1)
        except requests.Timeout:
            colorized_text(text='A connection timeout has occurred.', color='red')
            sys.exit(1)
        return None

    @classmethod
    def _decoded_json(cls, json_data: dict) -> dict:
        """
        Extracts specific information related to an IP address that was
        queried in the IP Geolocation database located at https://ip-api.com.

        :return: dictionary of parsed information
        :rtype: dict
        """
        ip_address = json.dumps(json_data["query"])
        organization_name = json.dumps(json_data["org"])
        isp_name = json.dumps(json_data["isp"])
        country_code = json.dumps(json_data["countryCode"])
        region_name = json.dumps(json_data["regionName"])
        city_name = json.dumps(json_data["city"])
        longitude = json.dumps(json_data["lat"])
        latitude = json.dumps(json_data["lon"])
        timezone = json.dumps(json_data["timezone"])
        as_number = json.dumps(json_data["as"]).split(sep=" ", maxsplit=1)[0]

        extracted_data = {
            "ip_address": ip_address.strip('"'),
            "domain_name": organization_name.strip('"'),
            "as_number": as_number.strip('"'),
            "isp_name": isp_name.strip('"'),
            "country_code": country_code.strip('"'),
            "region_name": region_name,
            "city_name": city_name.strip('"'),
            "longitude": longitude.strip('"'),
            "latitude": latitude.strip('"'),
            "timezone": timezone.strip('"')
        }
        return extracted_data

    def query_geolocation_database(self) -> Union[dict | list[dict] | None]:
        """
        Processes the input data, which could be a single IP address
        or a list of IP address.  An IP address is queried against
        the IP Geolocation database located at https://ip-api.com

        :return: dict of data elements related to the input data
        :rtype: dict or list
        """
        if isinstance(self.lookup_value, str):
            data = IPGeoLocation._get_json_data(self.lookup_value)
            if data:
                return IPGeoLocation._decoded_json(data)
        elif isinstance(self.lookup_value, list):
            data_elements = []
            for item in self.lookup_value:
                data = IPGeoLocation._get_json_data(item)
                if data:
                    data_elements.append(IPGeoLocation._decoded_json(data))
            return data_elements
        return None
