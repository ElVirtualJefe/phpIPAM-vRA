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

def handler(context, inputs):

    global phpipam
    phpipam = phpipam_client(context, inputs)
    phpipam_client.do_deallocate_ip = do_deallocate_ip

    return phpipam.deallocate_ip()

def do_deallocate_ip(self, auth_credentials, cert):
    # Your implemention goes here

    deallocation_result = []
    try:
        headers = {'Content-Type': 'application/json'}
        headers['token'] = phpipam._get_auth_token(auth_credentials, cert)

        logging.info(f"phpIPAM DEALLOCATE inputs: {self.inputs}")

        for deallocation in self.inputs["ipDeallocations"]:
            deallocation_result.append(deallocate(self, cert, headers, deallocation))
    except Exception as e:
        raise e

    assert len(deallocation_result) > 0
    return {
        "ipDeallocations": deallocation_result
    }

def deallocate(self, cert, headers, deallocation):
    ip_range_id = deallocation["ipRangeId"]
    ip = deallocation["ipAddress"]

    logging.info(f"Deallocating ip {ip} from range {ip_range_id}")
    URL = phpipam._build_API_url(f"/addresses/{ip}/{ip_range_id}")
    phpipam._API_delete(URL,cert,headers)

    ## Plug your implementation here to deallocate an already allocated ip address
    ## ...
    ## Deallocation successful

    return {
        "ipDeallocationId": deallocation["id"],
        "message": "Success"
    }
