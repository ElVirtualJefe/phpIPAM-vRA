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
    phpipam_client.do_update_record = do_update_record

    return phpipam.update_record()

def do_update_record(self, auth_credentials, cert):
    # Your implemention goes here

    headers = {'Content-Type': 'application/json'}
    headers['token'] = phpipam._get_auth_token(auth_credentials, cert)

    update_result = []

    for update_record in self.inputs["addressInfos"]:
        update_result.append(update(self, cert, headers, update_record))

    assert len(update_result) > 0
    return {
        "updateResults": update_result
    }

def update(self, cert, headers, update_record):
    try:
        ## Plug your implementation here to update the MAC address of an already allocate ip record
        ## Search the record and update its MAC
        mac = update_record["macAddress"]
        ip = update_record["address"]

        URL = phpipam._build_API_url(f"/addresses/search/{ip}")
        addressId = phpipam._API_get(URL,cert,headers).json()["data"][0]["id"]

        URL = phpipam._build_API_url(f"/addresses/{addressId}")
        data = {
            "mac": mac
        }
        phpipam._API_patch(URL, cert, headers, data)

        return "Success"
    except Exception as e:
        logging.error(f"Failed to update record {update_record}: {e}")
        raise e
