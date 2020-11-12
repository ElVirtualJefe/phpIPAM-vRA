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



# pylint: disable=import-error
from phpipam_utils.phpipam_client import phpipam_client
from phpipam_utils.exceptions import InvalidCertificateException
# pylint: enable=import-error
import logging


'''
Example payload:

"inputs": {
    "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0",
    "endpointProperties": {
      "hostName": "sampleipam.sof-mbu.eng.vmware.com"
    }
  }
'''

def handler(context, inputs):

    global phpipam
    phpipam = phpipam_client(context, inputs)
    phpipam_client.do_validate_endpoint = do_validate_endpoint

    return phpipam.validate_endpoint()

def do_validate_endpoint(self, auth_credentials, cert):

    try:
        logging.info(f"phpIPAM - self.inputs: {self.inputs}")
        endpointProperties = self.inputs.get("endpoint",self.inputs)["endpointProperties"]
        #URL = "https://" + endpointProperties["hostName"] + "/api/" + endpointProperties["appID"] + "/user"
        URL = phpipam._build_API_url("/user")
        logging.info(f"phpIPAM - URL: {URL}")
        
        if endpointProperties["authType"] == "token":
            headers = {'Content-Type': 'application/json', 'token': endpointProperties["tokenKey"]}
            logging.info(f"phpIPAM API Headers: {headers}")
            response = phpipam._API_get(URL, cert, headers)
        else:
            username = auth_credentials["privateKeyId"]
            password = auth_credentials["privateKey"]

            logging.info(f"phpIPAM Username: {username}")

            headers = {'Content-Type': 'application/json'}
            logging.info(f"phpIPAM API Headers: {headers}")
            response = phpipam._API_post(URL,cert,headers,(username, password))

        logging.info(f"phpIPAM Request Complete!!!")
        
        logging.info(f"phpIPAM API Response: {response}")
        if response.status_code == 200:
            return {
                "message": "Validated successfully",
                "statusCode": "200"
            }
        else:
            raise Exception(f"Failed to connect: {str(response.content)}")
    except Exception as e:
        """ In case of SSL validation error, a InvalidCertificateException is raised.
            So that the IPAM SDK can go ahead and fetch the server certificate
            and display it to the user for manual acceptance.
        """

        logging.info(f"phpIPAM e: {str(e)}")

        if "SSLCertVerificationError" in str(e) or "CERTIFICATE_VERIFY_FAILED" in str(e) or 'certificate verify failed' in str(e):
            raise InvalidCertificateException("certificate verify failed", self.inputs["endpointProperties"]["hostName"], 443) from e

        raise e


