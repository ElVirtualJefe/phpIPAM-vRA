"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

import sys, os
print(os.path.abspath(''))
sys.path.append(os.path.abspath('') + "\\src\\main\\python\\commons")

import logging
import ipaddress
import re
# pylint: disable=import-error
from phpipam_utils.phpipam_client import phpipam_client
# pylint: enable=import-error

'''
Example payload:

"inputs": {
    "endpoint": {
      "id": "f097759d8736675585c4c5d272cd",
      "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0",
      "endpointProperties": {
        "hostName": "sampleipam.sof-mbu.eng.vmware.com",
        "certificate": "-----BEGIN CERTIFICATE-----\nMIID0jCCArqgAwIBAgIQQaJF55UCb58f9KgQLD/QgTANBgkqhkiG9w0BAQUFADCB\niTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1\nbm55dmFsZTERMA8GA1UEChMISW5mb2Jsb3gxFDASBgNVBAsTC0VuZ2luZWVyaW5n\nMSgwJgYDVQQDEx9pbmZvYmxveC5zb2YtbWJ1LmVuZy52bXdhcmUuY29tMB4XDTE5\nMDEyOTEzMDExMloXDTIwMDEyOTEzMDExMlowgYkxCzAJBgNVBAYTAlVTMRMwEQYD\nVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZhbGUxETAPBgNVBAoTCElu\nZm9ibG94MRQwEgYDVQQLEwtFbmdpbmVlcmluZzEoMCYGA1UEAxMfaW5mb2Jsb3gu\nc29mLW1idS5lbmcudm13YXJlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAMMLNTqbAri6rt/H8iC4UgRdN0qj+wk0R2blmD9h1BiZJTeQk1r9i2rz\nzUOZHvE8Bld8m8xJ+nysWHaoFFGTX8bOd/p20oJBGbCLqXtoLMMBGAlP7nzWGBXH\nBYUS7kMv/CG+PSX0uuB0pRbhwOFq8Y69m4HRnn2X0WJGuu+v0FmRK/1m/kCacHga\nMBKaIgbwN72rW1t/MK0ijogmLR1ASY4FlMn7OBHIEUzO+dWFBh+gPDjoBECTTH8W\n5AK9TnYdxwAtJRYWmnVqtLoT3bImtSfI4YLUtpr9r13Kv5FkYVbXov1KBrQPbYyp\n72uT2ZgDJT4YUuWyKpMppgw1VcG3MosCAwEAAaM0MDIwMAYDVR0RBCkwJ4cEChda\nCoIfaW5mb2Jsb3guc29mLW1idS5lbmcudm13YXJlLmNvbTANBgkqhkiG9w0BAQUF\nAAOCAQEAXFPIh00VI55Sdfx+czbBb4rJz3c1xgN7pbV46K0nGI8S6ufAQPgLvZJ6\ng2T/mpo0FTuWCz1IE9PC28276vwv+xJZQwQyoUq4lhT6At84NWN+ZdLEe+aBAq+Y\nxUcIWzcKv8WdnlS5DRQxnw6pQCBdisnaFoEIzngQV8oYeIemW4Hcmb//yeykbZKJ\n0GTtK5Pud+kCkYmMHpmhH21q+3aRIcdzOYIoXhdzmIKG0Och97HthqpvRfOeWQ/A\nPDbxqQ2R/3D0gt9jWPCG7c0lB8Ynl24jLBB0RhY6mBrYpFbtXBQSEciUDRJVB2zL\nV8nJiMdhj+Q+ZmtSwhNRvi2qvWAUJQ==\n-----END CERTIFICATE-----\n"
      }
    },
    "pagingAndSorting": {
      "maxResults": 1000,
      "pageToken": "789c55905d6e02310c84df7d91452a456481168ec04b55950344f9db55dadd384abc056e5f3b42adfa12299f279ec9ac7c5670e9b0045a4ad2430c93af7a465f3bc83d4f9e3aa8976e6681ce660c827770de2aa1a68c72dfc3cae74393999b2e4df302e72691373aa60199bd827398efac18810f87a952591c61817c849513999df0b6c11436d6d400effcfacc14f2099cd6768913c5a435a0fd0c8e20ab2dbcd147564a2228c93b60b99ae2d94efde6ac640a09d9331130c539367078c41c915067ac9122268dc350439bf3379e9bc01b32025e9bd111aa65c829e89e83f0135ba740572c5f525c73f95faa608e39e55e62c6fcbd37de9775b891212a758d59bceb7a0eb30d7c7f6cd35c1399984291053b30f29fc5feed6cedf7adfe21962ab17b8ebde5089b1fec0d97d7-e5c4e5a1d726f600c22ebfd9f186148a1449755fd79a69ceabfe2aa"
    }
  }
'''

def handler(context, inputs):

    global phpipam
    phpipam = phpipam_client(context, inputs)
    phpipam_client.do_get_ip_ranges = do_get_ip_ranges

    return phpipam.get_ip_ranges()

def do_get_ip_ranges(self, auth_credentials, cert):

    headers = {'Content-Type': 'application/json'}
    headers['token'] = phpipam._get_auth_token(auth_credentials, cert)

    URL = phpipam._build_API_url("/subnets")

    subnets = phpipam._API_get(URL,cert,headers).json()["data"]

    ipRanges = []
    for subnet in subnets:
        if re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', subnet["subnet"]) is None:
            continue

        #logging.info(f'Allow Requests = {subnet["allowRequests"]}')
        if subnet["allowRequests"] == "1":
            net = phpipam._API_get(phpipam._build_API_url('/subnets/'+subnet["id"]+'/'),cert,headers).json()["data"]
            network = ipaddress.IPv4Network(subnet["subnet"]+"/"+subnet["mask"])
            subnetPrefixLength = network.prefixlen
            cidr = network.with_prefixlen
            #logging.info(f'Populating subnet - {cidr}')
            #logging.info(f'Subnet = {subnet}')
            #logging.info(network[11])
            #startIpAddress = phpipam._API_get(phpipam._build_API_url('/subnets/'+subnet["id"]+'/first_free/'),cert,headers).json()["data"]
            startIpAddress = str(network[11])
            endIpAddress = str(network[-2])
            # Build ipRange Object
            ipRange = {}
            ipRange["id"] = subnet["id"]
            ipRange["name"] = cidr
            ipRange["description"] = subnet["description"]
            ipRange["startIPAddress"] = startIpAddress
            ipRange["endIPAddress"] = endIpAddress
            ipRange["ipVersion"] = 'IPv4'
            if "gatewayId" in net:
                #logging.info(f'gatewayId = {net["gatewayId"]}')
                #pass
                gatewayIp = phpipam._API_get(phpipam._build_API_url("/addresses/"+net["gatewayId"]+"/"),cert,headers).json()["data"]
                #logging.info(f'gatewayIp = {gatewayIp}')
                #logging.info(f'IP = {gatewayIp["ip"]}')
                ipRange["gatewayAddress"] = gatewayIp["ip"]
            if "nameservers" in subnet:
                ipRange["dnsServerAddresses"] = subnet["nameservers"]["namesrv1"].split(';')
            ipRange["subnetPrefixLength"] = subnetPrefixLength
            #ipRange["addressSpaceId"] = addressSpaceId
            if "custom_Domain" in subnet:
                ipRange["domain"] = subnet["custom_Domain"]
                ipRange["dnsSearchDomains"] = [subnet["custom_Domain"]]
            #ipRange["properties"] = None
            #ipRange["tags"] = None
            #logging.info(subnet["id"], cidr, subnet["description"], startIpAddress, endIpAddress, 'IPv4', addressSpaceId, gatewayAddress, subnetPrefixLength, dnsServerAddresses)
            ipRanges.append(ipRange)
    
    logging.info(ipRanges)

    ## If many IP ranges are expected on the IPAM server, it is considered a best practice
    ## to return them page by page instead of all at once.
    ## The vRA IPAM Service will propagate a pageToken string with each consecutive request
    ## until all pages are exhausted
    pageToken = self.inputs['pagingAndSorting'].get('pageToken', None) ## The first request that vRA sends is with 'None' pageToken
    maxResults = self.inputs['pagingAndSorting'].get('maxResults', 20)

    ## Plug your implementation here to collect all the ranges from the external IPAM system
    result_ranges, next_page_token = collect_ranges(ipRanges,pageToken,maxResults)

    result = {
        "ipRanges": result_ranges
    }

    ## Return the next page token so that vRA can process the first page and then fetch the second page or ranges with the next request
    if next_page_token is not None:
        logging.info("There are more IP Ranges...")
        result["nextPageToken"] = next_page_token
    else:
        logging.info("This is the final page of IP Ranges...")

    return result

def collect_ranges(ipRanges,pageToken,maxResults):
    logging.info("Collecting ranges")

    result = []
    next_page_token = None
    if pageToken is None:
        pageEnd = len(ipRanges) if (int(maxResults) > len(ipRanges)) else (int(maxResults))
        for i in range(0,pageEnd):
            result.append(ipRanges[i])
    else:
        pageEnd = len(ipRanges) if (int(pageToken) + int(maxResults) >= len(ipRanges)) else (int(pageToken) + int(maxResults))
        for i in range(int(pageToken),pageEnd):
            result.append(ipRanges[i])
    
    if (pageEnd >= len(ipRanges)):
        next_page_token = None
    else:
        next_page_token = pageEnd

    return result, next_page_token

