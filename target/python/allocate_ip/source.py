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

import requests
# pylint: disable=import-error
from phpipam_utils.phpipam_client import phpipam_client
# pylint: enable=import-error
import logging
import ipaddress

"""
Example payload

"inputs": {
    "resourceInfo": {
      "id": "11f912e71454a075574a728848458",
      "name": "external-ipam-it-mcm-323412",
      "description": "test",
      "type": "VM",
      "owner": "mdzhigarov@vmware.com",
      "orgId": "ce811934-ea1a-4f53-b6ec-465e6ca7d126",
      "properties": {
        "osType": "WINDOWS",
        "vcUuid": "ff257ed9-070b-45eb-b2e7-d63926d5bdd7",
        "__moref": "VirtualMachine:vm-288560",
        "memoryGB": "4",
        "datacenter": "Datacenter:datacenter-2",
        "provisionGB": "1",
        "__dcSelfLink": "/resources/groups/b28c7b8de065f07558b1612fce028",
        "softwareName": "Microsoft Windows XP Professional (32-bit)",
        "__computeType": "VirtualMachine",
        "__hasSnapshot": "false",
        "__placementLink": "/resources/compute/9bdc98681fb8b27557252188607b8",
        "__computeHostLink": "/resources/compute/9bdc98681fb8b27557252188607b8"
      }
    },
    "ipAllocations": [
      {
        "id": "111bb2f0-02fd-4983-94d2-8ac11768150f",
        "ipRangeIds": [
          "network/ZG5zLm5ldHdvcmskMTAuMjMuMTE3LjAvMjQvMA:10.23.117.0/24/default"
        ],
        "nicIndex": "0",
        "isPrimary": "true",
        "size": "1",
        "properties": {
          "__moref": "DistributedVirtualPortgroup:dvportgroup-307087",
          "__dvsUuid": "0c 8c 0b 50 46 b6 1c f2-e8 63 f4 24 24 d7 24 6c",
          "__dcSelfLink": "/resources/groups/abe46b8cfa663a7558b28a6ffe088",
          "__computeType": "DistributedVirtualPortgroup",
          "__portgroupKey": "dvportgroup-307087"
        }
      }
    ],
    "endpoint": {
      "id": "f097759d8736675585c4c5d272cd",
      "endpointProperties": {
        "hostName": "sampleipam.sof-mbu.eng.vmware.com",
        "projectId": "111bb2f0-02fd-4983-94d2-8ac11768150f",
        "providerId": "d8a5e3f2-d839-4365-af5b-f48de588fdc1",
        "certificate": "-----BEGIN CERTIFICATE-----\nMIID0jCCArqgAwIBAgIQQaJF55UCb58f9KgQLD/QgTANBgkqhkiG9w0BAQUFADCB\niTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1\nbm55dmFsZTERMA8GA1UEChMISW5mb2Jsb3gxFDASBgNVBAsTC0VuZ2luZWVyaW5n\nMSgwJgYDVQQDEx9pbmZvYmxveC5zb2YtbWJ1LmVuZy52bXdhcmUuY29tMB4XDTE5\nMDEyOTEzMDExMloXDTIwMDEyOTEzMDExMlowgYkxCzAJBgNVBAYTAlVTMRMwEQYD\nVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZhbGUxETAPBgNVBAoTCElu\nZm9ibG94MRQwEgYDVQQLEwtFbmdpbmVlcmluZzEoMCYGA1UEAxMfaW5mb2Jsb3gu\nc29mLW1idS5lbmcudm13YXJlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAMMLNTqbAri6rt/H8iC4UgRdN0qj+wk0R2blmD9h1BiZJTeQk1r9i2rz\nzUOZHvE8Bld8m8xJ+nysWHaoFFGTX8bOd/p20oJBGbCLqXtoLMMBGAlP7nzWGBXH\nBYUS7kMv/CG+PSX0uuB0pRbhwOFq8Y69m4HRnn2X0WJGuu+v0FmRK/1m/kCacHga\nMBKaIgbwN72rW1t/MK0ijogmLR1ASY4FlMn7OBHIEUzO+dWFBh+gPDjoBECTTH8W\n5AK9TnYdxwAtJRYWmnVqtLoT3bImtSfI4YLUtpr9r13Kv5FkYVbXov1KBrQPbYyp\n72uT2ZgDJT4YUuWyKpMppgw1VcG3MosCAwEAAaM0MDIwMAYDVR0RBCkwJ4cEChda\nCoIfaW5mb2Jsb3guc29mLW1idS5lbmcudm13YXJlLmNvbTANBgkqhkiG9w0BAQUF\nAAOCAQEAXFPIh00VI55Sdfx+czbBb4rJz3c1xgN7pbV46K0nGI8S6ufAQPgLvZJ6\ng2T/mpo0FTuWCz1IE9PC28276vwv+xJZQwQyoUq4lhT6At84NWN+ZdLEe+aBAq+Y\nxUcIWzcKv8WdnlS5DRQxnw6pQCBdisnaFoEIzngQV8oYeIemW4Hcmb//yeykbZKJ\n0GTtK5Pud+kCkYmMHpmhH21q+3aRIcdzOYIoXhdzmIKG0Och97HthqpvRfOeWQ/A\nPDbxqQ2R/3D0gt9jWPCG7c0lB8Ynl24jLBB0RhY6mBrYpFbtXBQSEciUDRJVB2zL\nV8nJiMdhj+Q+ZmtSwhNRvi2qvWAUJQ==\n-----END CERTIFICATE-----\n"
      },
      "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0"
    }
  }
"""

def handler(context, inputs):

    global phpipam
    phpipam = phpipam_client(context, inputs)
    phpipam_client.do_allocate_ip = do_allocate_ip

    return phpipam.allocate_ip()

def do_allocate_ip(self, auth_credentials, cert):

    allocation_result = []

    try:
        headers = {'Content-Type': 'application/json'}
        headers['token'] = phpipam._get_auth_token(auth_credentials, cert)

        ## Using this as a test for rolling back IP Allocations:
        #allocation_result = {'ipAllocations': [{'ipAllocationId': '111bb2f0-02fd-4983-94d2-8ac11768150f', 'ipRangeId': '8', 'ipVersion': 'IPv4', 'ipAddresses': ['172.16.108.41', '172.16.108.64']}]}
        #rollback(allocation_result,cert,headers)
        #pass

        for allocation in self.inputs["ipAllocations"]:
            allocation_result.append(allocate(self, cert, headers, allocation))
    except Exception as e:
        try:
            rollback(allocation_result, cert, headers)
        except Exception as rollback_e:
            logging.error(f"Error during rollback of allocation result {str(allocation_result)}")
            logging.error(rollback_e)
        raise e

    assert len(allocation_result) > 0
    return {
        "ipAllocations": allocation_result
    }

def allocate(self, cert, headers, allocation):

    last_error = None
    #logging.info(str(allocation))

    i = 0
    ipAddresses = []

    while i < int(allocation["size"]):

        for range_id in allocation["ipRangeIds"]:

            #logging.info(range_id)

            URL = phpipam._build_API_url(f"/subnets/{range_id}")

            #logging.info(str(phpipam._API_get(URL,cert,headers).json()))
            ipRange = phpipam._API_get(URL,cert,headers).json()["data"]
            #logging.info(str(ipRange))

            logging.info(f"Allocating from range {ipRange['subnet'] + '/' + ipRange['mask']}")
            try:
                ipAddresses.append(allocate_in_range(self, range_id, allocation, cert, headers))
                i += 1
                break
            except Exception as e:
                last_error = e
                logging.error(f"Failed to allocate from range {range_id}: {str(e)}")

        if last_error is not None:
            logging.error("No more ranges. Raising last error")
            raise last_error

    result = {
        "ipAllocationId": allocation["id"],
        "ipRangeId": range_id,
        "ipVersion": "IPv4",
        "ipAddresses": ipAddresses
    }

    return result


def allocate_in_range(self, range_id, allocation, cert, headers):

    ipRange = phpipam._API_get(
        phpipam._build_API_url(f"/subnets/{range_id}"),
        cert,
        headers
    ).json()["data"]
    network = ipaddress.IPv4Network(ipRange["subnet"]+"/"+ipRange["mask"])

    success = False

    logging.info(f"phpIPAM allocat_in_range inputs: {self.inputs}")

    try:

        while not success:
            URL = phpipam._build_API_url(f"/addresses/first_free/{range_id}")
            resource = self.inputs.get("resourceInfo")
            logging.info(f"phpIPAM Resource: {str(resource)}")

            result = phpipam._API_get(URL, cert, headers).json()
            if result["success"] == False:
                raise Exception(f"IP not allocated: {result['message']}")

            ipFirstFree = result["data"]
            URL = phpipam._build_API_url("/addresses")

            data = {}

            data["ip"] = ipFirstFree
            data["subnetId"] = int(range_id)
            if network[1] == ipaddress.IPv4Address(ipFirstFree):
                data["is_gateway"] = True
            
            if network[11] > ipaddress.IPv4Address(ipFirstFree):
            
                data["hostname"] = ""
                data["note"] = "Allocated by vRealize Automation"
                data["description"] = "Reserved for Network Team"
                data["owner"] = "Daniel McIntire"
                data["tag"] = int(phpipam._API_get(
                    phpipam._build_API_url("/addresses/tags"),
                    cert,
                    headers,
                    {
                        'filter_by': 'type',
                        'filter_value': 'Reserved',
                        'filter_match': 'full'
                    }
                ).json()["data"][0]["id"])

                logging.warning(f"Skipping and Reserving IP {ipFirstFree}")
                result = phpipam._API_post(URL, cert, headers, data).json()
                continue

            else:
                data["description"] = resource["description"]
                data["note"] = "Allocated by vRealize Automation"
                data["owner"] = resource["owner"]
                data["port"] = allocation["nicIndex"]
                data["hostname"] = resource["name"]

                result = phpipam._API_post(URL, cert, headers, data).json()
                if result["code"] == 201:
                    return ipFirstFree
                else:
                    raise Exception(f"Not sure of result...  Please contact the Developer...  Result Code: {result['code']}, Result Message: {result['message']}")

            if result["success"] == False:
                raise Exception(f"IP not allocated: {result['message']}")

    except Exception as e:
        raise e

## Rollback any previously allocated addresses in case this allocation request contains multiple ones and failed in the middle
def rollback(allocation_result, cert, headers):
    logging.info(allocation_result)
    for allocation in reversed(allocation_result["ipAllocations"]):
        logging.info(f"Rolling back allocation {str(allocation)}")
        for allocatedIP in reversed(allocation.get("ipAddresses")):
            URL = phpipam._build_API_url(f"/addresses/{allocatedIP}/{allocation['ipRangeId']}")
            logging.info(f"Rolling back IP Allocation: {allocatedIP}")
            phpipam._API_delete(URL,cert,headers)

    return


