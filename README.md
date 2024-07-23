# Network Forensics Tools

This repository contains a collection of Python scripts designed for specific forensics operations. These tools are useful for conducting ARIN lookups, IP geolocation, IP Reputation, MAC address lookups, and data extraction from various file types such as text files and spreadsheets.

## Features

- **ARIN Lookup**: Retrieve information about IP address allocation from the American Registry for Internet Numbers (ARIN).
- **IP Geolocation**: Determine the geographical location of an IP address.
- **IP Reputation**: Determine the reputation of an IP address.
- **MAC Address Lookup**: Find the manufacturer and other details about a MAC address.
- **Data Extraction Tools**: Extract MAC and IP addresses from text files, cvs files and other documents.

## Usage

The modules can be run using either the command-line or within an IDE, such as PyCharm.

### ARIN Lookup

To perform an ARIN lookup using the command-line (cli.py) script:

```sh

username@computername forensics_tools % python3 cli.py arin 208.66.195.10    
[{'ip_address': '208.66.195.10', 'organization': 'VOLICO', 'network': '208.66.192.0-208.66.195.255', 'cidr': '208.66.192.0/22'}]

```

To perform an ARIN lookup using another script. 

```py
from arin_whois_lookup import ArinWhois

results = ArinWhois('208.66.195.10').query_whois()
print(results)
{'ip_address': '208.66.195.10', 'organization': 'VOLICO', 'network': '208.66.192.0-208.66.195.255', 'cidr': '208.66.192.0/22'}

```

### IP Geolocation

To determine the geolocation of an IP address using the command-line (cli.py) script:

```sh

username@computernameforensics_tools  % python3 cli.py geo 208.66.195.10  
{'ip_address': '208.66.195.10', 'domain_name': 'VOLICO', 'as_number': 'AS33724', 'isp_name': 'VOLICO', 'country_code': 'US', 'region_name': '"Florida"', 'city_name': 'Miami', 'longitude': '25.7617', 'latitude': '-80.1918', 'timezone': 'America/New_York'}

```

To determine the geolocation of an IP address using another script.

```py

from ip_geolocation_lookup import IPGeoLocation

results = IPGeoLocation('208.66.195.10').query_geolocation_database()
print(results)
{'ip_address': '208.66.195.10', 'domain_name': 'VOLICO', 'as_number': 'AS33724', 'isp_name': 'VOLICO', 'country_code': 'US', 'region_name': '"Florida"', 'city_name': 'Miami', 'longitude': '25.7617', 'latitude': '-80.1918', 'timezone': 'America/New_York'}

```

### IP Reputation

To determine the reputation of an IP address using the command-line (cli.py) script:

```sh

username@computername forensics_tools  % python3 cli.py abuse 208.66.195.10 my_api_key
{'ip_address': '208.66.195.10', 'domain_name': 'volico.com', 'host_name': '[]', 'usage_type': 'Data Center/Web Hosting/Transit', 'isp_name': 'Volico', 'country_code': 'US', 'confidence_of_abuse': '0', 'level_of_abuse': 'not malicious', 'white_listed': 'null', 'tor_node': 'false', 'number_of_times_reported': '0', 'date_last_reported': 'null'}

```

To determine the reputation of an IP address using another script. 

```py
from ip_reputation_lookup import IPReputation

results = IPReputation('208.66.195.10', 'my_api_key').query_abuse_database()
print(results)
{'ip_address': '208.66.195.10', 'domain_name': 'volico.com', 'host_name': '[]', 'usage_type': 'Data Center/Web Hosting/Transit', 'isp_name': 'Volico', 'country_code': 'US', 'confidence_of_abuse': '0', 'level_of_abuse': 'not malicious', 'white_listed': 'null', 'tor_node': 'false', 'number_of_times_reported': '0', 'date_last_reported': 'null'}

```

### MAC Address Lookup

To find details about a MAC address using the command-line (cli.py) script:

```sh

username@computername forensics_tools  % python3 cli.py mac 04:7b:cb:3b:75:94  
{'mac_address': '04:7b:cb:3b:75:94', 'registered_organization': 'Universal Global Scientific Industrial Co., Ltd.', 'organization_address': '141, Lane 351, Taiping Road, Sec.1,Tsao Tuen, Nan-Tou Taiwan 54261, TW', 'country': 'TW'}

```

To find details about a MAC address using another script. 

```py
from mac_address_vendor_lookup import MacAddressLookup

results = MacAddressLookup('04:7b:cb:3b:75:94').lookup_address_information()
print(results)
{'mac_address': '04:7b:cb:3b:75:94', 'registered_organization': 'Universal Global Scientific Industrial Co., Ltd.', 'organization_address': '141, Lane 351, Taiping Road, Sec.1,Tsao Tuen, Nan-Tou Taiwan 54261, TW', 'country': 'TW'}

```

## License

This project is licensed under the GPL-3.0 license. See the [LICENSE](/LICENSE) file for more details.
