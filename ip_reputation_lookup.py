#!/usr/bin/env python3

"""
This Python script is designed to query the AbuseIPDB datebase for information related
to an IP address potential involvement in malicious activity such as spamming, hacking
attempts, DDoS attacks or other activities.
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


class IPReputation:
    """
    Purpose
    ----------

    This Python script is designed to query the AbuseIPDB datebase for information related
    to an IP address potential involvement in malicious activity such as spamming, hacking
    attempts, DDoS attacks or other activities.

    Usage Examples
    ----------

    # IPv4 example str
    IPReputation('67.21.32.233').query_abuse_database()

    # IPv4 example list
    ip_addresses = ['67.21.32.233', '67.21.32.230']
    IPReputation('67.21.32.233').query_abuse_database()

    # IPv6 example str
    IPReputation('2600:1700:6c15:4050:83f:c3a:4dd8:f3ad').query_abuse_database()

    # IPv6 example list
    ip_addresses = ['2600:1700:6c15:4050:83f:c3a:4dd8:f3ad', '2600:1700:6c15:4050:83f:c3a:4dd8:f3ad']
    IPReputation(ip_addresses).query_abuse_database()

    # Combined example
    ip_addresses = ['67.21.32.233', '2600:1700:6c15:4050:83f:c3a:4dd8:f3ad']
    IPReputation(ip_addresses).query_abuse_database()

    Parameters
    ----------
    :param lookup_value: Input data containing the IP addresses to obtain information for
    """

    def __init__(self,
                 lookup_value: str | list = '',
                 api_key: str = ''):
        self.lookup_value = lookup_value
        self.api_key = api_key

    @staticmethod
    def _get_json_data(ip_address: str, api_key: str) -> Union[dict, None]:
        """
        Obtains the reputation information for the IP address being queried.

        :param ip_address: IP address being queried
        :return: dictionary of reputation data
        :rtype: dictionary
        """
        sleep(randint(a=1, b=3))

        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': ip_address,
            # The max age in days must be between 1 and 365
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            # API Key
            # https://www.abuseipdb.com/pricing
            'Key': api_key
        }
        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=(5, 10))
            decoded_response = json.loads(response.text)
            if response.status_code == 401:
                error_message = json.dumps(decoded_response["errors"][0]['detail']).strip('"')
                colorized_text(text=error_message, color='red')
            elif response.status_code == 422:
                error_message = json.dumps(decoded_response["errors"][0]['detail']).strip('"')
                colorized_text(text=error_message, color='red')
            elif response.status_code == 429:
                error_message = json.dumps(decoded_response["errors"][0]['detail']).strip('"')
                colorized_text(text=error_message, color='red')
            elif response.status_code == 200:
                return decoded_response
        except requests.ConnectionError:
            colorized_text(text='A ConnectionError has occurred.', color='red')
            sys.exit(1)
        except requests.Timeout:
            colorized_text(text='A connection timeout has occurred.', color='red')
            sys.exit(1)
        return None

    @staticmethod
    def _determine_abuse_level(confidence_score: int) -> Union[str | None]:
        """
        Checks the reputation confidence score for a specific IP address
        and returns information related to it being either malicious or
        not malicious.

        :param confidence_score: reputation source
        :return: string
        :rtype: str
        """
        if confidence_score == 0:
            return "not malicious"
        elif confidence_score == 100:
            return "is malicious and warrants additional investigation"
        elif 100 > confidence_score > 25:
            return "likley malicious and warrants further investigation"
        elif 0 < confidence_score <= 25:
            return "likley not malicious but warrants further investigation"
        return None

    @classmethod
    def _decoded_json(cls, json_data: dict) -> dict:
        """
        Extracts specific information related to an IP address that was
        queried in the AbuseIPDB database.

        :return: dictionary of parsed information
        :rtype: dict
        """
        ip_address = json.dumps(json_data["data"]["ipAddress"])
        domain_name = json.dumps(json_data["data"]["domain"])
        host_name = json.dumps(json_data["data"]["hostnames"])
        usage_type = json.dumps(json_data["data"]["usageType"])
        isp_name = json.dumps(json_data["data"]["isp"])
        country_code = json.dumps(json_data["data"]["countryCode"])
        confidence_of_abuse = json.dumps(json_data["data"]["abuseConfidenceScore"])
        level_of_abuse = IPReputation._determine_abuse_level(int(confidence_of_abuse))
        white_listed = json.dumps(json_data["data"]["isWhitelisted"])
        tor_node = json.dumps(json_data["data"]["isTor"])
        times_reported = json.dumps(json_data["data"]["totalReports"])
        date_last_reported = json.dumps(json_data["data"]["lastReportedAt"])

        extracted_data = {
            "ip_address": ip_address.strip('"'),
            "domain_name": domain_name.strip('"'),
            "host_name": host_name,
            "usage_type": usage_type.strip('"'),
            "isp_name": isp_name.strip('"'),
            "country_code": country_code.strip('"'),
            "confidence_of_abuse": confidence_of_abuse.strip('"'),
            "level_of_abuse": level_of_abuse,
            "white_listed": white_listed.strip('"'),
            "tor_node": tor_node.strip('"'),
            "number_of_times_reported": times_reported.strip('"'),
            "date_last_reported": date_last_reported.strip('"')
        }
        return extracted_data

    def query_abuse_database(self) -> Union[dict | list[dict] | None]:
        """
        Processes the input data, which could be a single IP address
        or a list of IP address.  An IP address is queried against
        the AbuseIPDB database.

        :return: dict of data elements related to the input data
        :rtype: dict or list
        """
        if isinstance(self.lookup_value, str):
            data = IPReputation._get_json_data(self.lookup_value, self.api_key)
            if data:
                return IPReputation._decoded_json(data)
        elif isinstance(self.lookup_value, list):
            data_elements = []
            for item in self.lookup_value:
                data = IPReputation._get_json_data(item, self.api_key)
                if data:
                    data_elements.append(IPReputation._decoded_json(data))
            return data_elements
        return None
