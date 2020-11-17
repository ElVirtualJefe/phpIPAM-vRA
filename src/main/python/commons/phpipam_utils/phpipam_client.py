import json
import tempfile
import os
import logging
# pylint: disable=import-error
from phpipam_utils.exceptions import InvalidCertificateException
# pylint: enable=import-error
import requests



class phpipam_client(object):
    """
        phpIPAM Client Object.

        This Object allows for creating connections with phpIPAM
        The client object can use any supported authentication methods
            available in phpIPAM.
        

    """

    def __init__(self, context, inputs):

        self.context = context
        self.inputs = inputs

        # Setup the logging globally
        self._setup_logger()

    def validate_endpoint(self):

        cert = None
        try:
            auth_credentials = self._get_auth_credentials()
            cert = self._get_cert()

            #logging.info(f"phpIPAM cert: {cert}")

            return self.do_validate_endpoint(auth_credentials, cert)
        except InvalidCertificateException as e:
            return {
                "certificateInfo": {
                    "certificate": self._fetch_server_certificate(e.host, e.port)
                },
                "error": self._build_error_response("3002", str(e))["error"] ## Return special status code "3002" on invalid certificate
            }
        finally:
            if cert is not None and type(cert) is str:
                os.unlink(cert)

    def get_ip_ranges(self):

        cert = None
        try:
            auth_credentials = self._get_auth_credentials()
            cert = self._get_cert()

            result = self.do_get_ip_ranges(auth_credentials, cert)

            # Validation of returned result
            err_msg = "{} is mandatory part of the response schema and must be present in the response"
            assert result.get("ipRanges") is not None, err_msg.format("ipRanges")
            assert isinstance(result["ipRanges"], list), "ipRanges must be a list type"
            for i in range(len(result["ipRanges"])):
                assert result["ipRanges"][i].get("id") is not None, err_msg.format(f"ipRanges[{i}]['id']")
                assert result["ipRanges"][i].get("name") is not None, err_msg.format(f"ipRanges[{i}]['name']")
                assert result["ipRanges"][i].get("startIPAddress") is not None, err_msg.format(f"ipRanges[{i}]['startIPAddress']")
                assert result["ipRanges"][i].get("endIPAddress") is not None, err_msg.format(f"ipRanges[{i}]['endIPAddress']")
                assert result["ipRanges"][i].get("ipVersion") is not None, err_msg.format(f"ipRanges[{i}]['ipVersion']")
                assert result["ipRanges"][i].get("subnetPrefixLength") is not None, err_msg.format(f"ipRanges[{i}]['subnetPrefixLength']")

            return result
        finally:
            if cert is not None and type(cert) is str:
                os.unlink(cert)

    def allocate_ip(self):

        cert = None
        try:
            auth_credentials = self._get_auth_credentials()
            cert = self._get_cert()

            result = self.do_allocate_ip(auth_credentials, cert)

              # Validation of returned result
            err_msg = "{} is mandatory part of the response schema and must be present in the response"
            assert result.get("ipAllocations") is not None, err_msg.format("ipAllocations")
            assert isinstance(result["ipAllocations"], list), "ipAllocations must be a list type"
            assert len(result["ipAllocations"]) == len(self.inputs["ipAllocations"]), "Size of ipAllocations in the inputs is different than the one in the outputs"

            for i in range(len(result["ipAllocations"])):
                assert result["ipAllocations"][i].get("ipAllocationId") is not None, err_msg.format(f"ipAllocations[{i}]['ipAllocationId']")
                assert result["ipAllocations"][i].get("ipRangeId") is not None, err_msg.format(f"ipAllocations[{i}]['ipRangeId']")
                assert result["ipAllocations"][i].get("ipVersion") is not None, err_msg.format(f"ipAllocations[{i}]['ipVersion']")
                assert result["ipAllocations"][i].get("ipAddresses") is not None, err_msg.format(f"ipAllocations[{i}]['ipAddresses']")
                assert isinstance(result["ipAllocations"][i]["ipAddresses"], list), f"ipAllocations[{i}]['ipAddresses'] must be a list type"
                assert len(result["ipAllocations"][i]["ipAddresses"]) > 0, f"ipAllocations[{i}]['ipAddresses'] must not be empty"

                for allocation in self.inputs["ipAllocations"]:
                    found = False
                    if allocation["id"] == result["ipAllocations"][i]["ipAllocationId"]:
                        found = True
                        break

                    assert found, f"Allocation result with id {result['ipAllocations'][i]['ipAllocationId']} not found"

            return result
        finally:
            if cert is not None and type(cert) is str:
                os.unlink(cert)

    def deallocate_ip(self):

        cert = None
        try:
            auth_credentials = self._get_auth_credentials()
            cert = self._get_cert()

            result = self.do_deallocate_ip(auth_credentials, cert)

            # Validation of returned result
            err_msg = "{} is mandatory part of the response schema and must be present in the response"
            assert result.get("ipDeallocations") is not None, err_msg.format("ipDeallocations")
            assert isinstance(result["ipDeallocations"], list), "ipDeallocations must be a list type"
            assert len(result["ipDeallocations"]) == len(self.inputs["ipDeallocations"]), "Size of ipDeallocations in the inputs is different than the one in the outputs"
            for i in range(len(result["ipDeallocations"])):
                assert result["ipDeallocations"][i].get("ipDeallocationId") is not None, err_msg.format(f"ipDeallocations[{i}]['ipDeallocationId']")

                for deallocation in self.inputs["ipDeallocations"]:
                    found = False
                    if deallocation["id"] == result["ipDeallocations"][i]["ipDeallocationId"]:
                        found = True
                        break

                    assert found, f"Deallocation result with id {result['ipDeallocations'][i]['ipDeallocationId']} not found"

            return result
        finally:
            if cert is not None and type(cert) is str:
                os.unlink(cert)

    def update_record(self):

        cert = None
        try:
            auth_credentials = self._get_auth_credentials()
            cert = self._get_cert()

            return self.do_update_record(auth_credentials, cert)
        finally:
            if cert is not None and type(cert) is str:
                os.unlink(cert)

    def get_ip_blocks(self):

        cert = None
        try:
            auth_credentials = self._get_auth_credentials()
            cert = self._get_cert()

            result = self.do_get_ip_blocks(auth_credentials, cert)

            # Validation of returned result
            err_msg = "{} is mandatory part of the response schema and must be present in the response"
            assert result.get("ipBlocks") is not None, err_msg.format("ipBlocks")
            assert isinstance(result["ipBlocks"], list), "ipRanges must be a list type"
            for i in range(len(result["ipBlocks"])):
                assert result["ipBlocks"][i].get("id") is not None, err_msg.format(f"ipBlocks[{i}]['id']")
                assert result["ipBlocks"][i].get("name") is not None, err_msg.format(f"ipBlocks[{i}]['name']")
                assert result["ipBlocks"][i].get("ipBlockCIDR") is not None, err_msg.format(f"ipBlocks[{i}]['ipBlockCIDR']")
                assert result["ipBlocks"][i].get("ipVersion") is not None, err_msg.format(f"ipBlocks[{i}]['ipVersion']")

            return result
        finally:
            if cert is not None and type(cert) is str:
                os.unlink(cert)

    def allocate_ip_range(self):

        cert = None
        try:
            auth_credentials = self._get_auth_credentials()
            cert = self._get_cert()

            result = self.do_allocate_ip_range(auth_credentials, cert)

             # Validation of returned result
            err_msg = "{} is mandatory part of the response schema and must be present in the response"
            assert result.get("ipRange") is not None, err_msg.format("ipRange")
            assert result["ipRange"].get("id") is not None, err_msg.format(f"ipRange['id']")
            assert result["ipRange"].get("name") is not None, err_msg.format(f"ipRange['name']")
            assert result["ipRange"].get("startIPAddress") is not None, err_msg.format(f"ipRange['startIPAddress']")
            assert result["ipRange"].get("endIPAddress") is not None, err_msg.format(f"ipRange['endIPAddress']")
            assert result["ipRange"].get("ipVersion") is not None, err_msg.format(f"ipRange['ipVersion']")
            assert result["ipRange"].get("subnetPrefixLength") is not None, err_msg.format(f"ipRange['subnetPrefixLength']")

            return result
        finally:
            if cert is not None and type(cert) is str:
                os.unlink(cert)

    def deallocate_ip_range(self):

        cert = None
        try:
            auth_credentials = self._get_auth_credentials()
            cert = self._get_cert()

            return self.do_deallocate_ip_range(auth_credentials, cert)
        finally:
            if cert is not None and type(cert) is str:
                os.unlink(cert)

    def do_validate_endpoint(self, auth_credentials, cert):
        raise Exception("Method do_validate_endpoint(self, auth_credentials, cert) not implemented")

    def do_get_ip_ranges(self, auth_credentials, cert):
        raise Exception("Method do_get_ip_ranges(self, auth_credentials, cert) not implemented")

    def do_allocate_ip(self, auth_credentials, cert):
        raise Exception("Method do_allocate_ip(self, auth_credentials, cert) not implemented")

    def do_deallocate_ip(self, auth_credentials, cert):
        raise Exception("Method do_deallocate_ip(self, auth_credentials, cert) not implemented")

    def do_update_record(self, auth_credentials, cert):
        raise Exception("Method do_update_record(self, auth_credentials, cert) not implemented")

    def do_get_ip_blocks(self, auth_credentials, cert):
        raise Exception("Method do_get_ip_blocks(self, auth_credentials, cert) not implemented")

    def do_allocate_ip_range(self, auth_credentials, cert):
        raise Exception("Method do_allocate_ip_range(self, auth_credentials, cert) not implemented")

    def do_deallocate_ip_range(self, auth_credentials, cert):
        raise Exception("Method do_deallocate_ip_range(self, auth_credentials, cert) not implemented")


    def _get_cert(self):
        if self._is_mock_request(): # Used for testing purposes within VMware
            return False

        inputs = self.inputs.get("endpoint", self.inputs)
        certificate = inputs["endpointProperties"].get("certificate", None)
        if certificate is not None:
            cert = tempfile.NamedTemporaryFile(mode='w', delete=False)
            cert.write(certificate)
            cert.close()
            return cert.name
        else:
            return True

    """ Fetches the server certificate of the host.
        Used in case the certificate is not automatically trusted
    """
    def _fetch_server_certificate(self, hostname, port):

        logging.info(f"Fetching certificate of {hostname}")
        import ssl
        import socket
        # pylint: disable=import-error
        from OpenSSL import SSL
        from OpenSSL import crypto
        # pylint: enable=import-error
        import os
        import idna

        hostname_idna = idna.encode(hostname)
        proxy = os.environ.get("http_proxy", None)
        if proxy is not None:
            from urllib.parse import urlparse
            o = urlparse(proxy)
            PROXY_ADDR = (o.hostname, o.port)
            CONNECT = "CONNECT %s:%s HTTP/1.0\r\nConnection: close\r\n\r\n" % (hostname, port)
            logging.info(f"HTTP Proxy is configured. Sending CONNECT command to {proxy}: {CONNECT}")
            CONNECT = bytes(CONNECT, "utf-8")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(PROXY_ADDR)
            sock.send(CONNECT)
            logging.info(sock.recv(4096))
        else:
            sock = socket.socket()
            sock.connect((hostname, port))

        ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        certs = sock_ssl.get_peer_cert_chain()
        sb = ""
        for cert in certs:
            cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            cert = cert.decode()
            sb += cert

        sock_ssl.shutdown()
        sock_ssl.close()
        sock.close()

        return sb

    def _build_error_response(self, error_code, error_message):
        return {
            "error": {
                "errorCode": error_code,
                "errorMessage": error_message
            }
        }

    """ Fetches the auth credentials from vRA """
    def _get_auth_credentials(self):

        if self._is_mock_request(): # Used for testing purposes within VMware
            #return {"privateKeyId": "token", "privateKey":"Password1!"}
            return {"privateKeyId": "a-jphelps", "privateKey":"hVZMd^#4y^*UOC1I!Soi!rdH"}

        logging.info("Querying for phpIPAM auth credentials")
        #logging.info(f"phpIPAM._get_auth_credentials - self.inputs: {self.inputs}")
        inputs = self.inputs.get("endpoint", self.inputs)
        #logging.info(f"phpIPAM._get_auth_credentials - inputs: {inputs}")
        auth_credentials_link = inputs["authCredentialsLink"]
        #logging.info(f"phpIPAM._get_auth_credentials - auth_credentials_link: {auth_credentials_link}")
        auth_credentials_response = self.context.request(auth_credentials_link, 'GET', '') ## Integrators can use context.request() to call CAS/Prelude REST endpoints
        if auth_credentials_response["status"] == 200:
            logging.info("phpIPAM Credentials obtained successfully!")
            return json.loads(auth_credentials_response["content"])

        raise Exception(f"Failed to obtain auth credentials from {auth_credentials_link}: {str(auth_credentials_response)}")

    def _setup_logger(self):
        logger = logging.getLogger()
        if logger.handlers:
            for handler in logger.handlers:
                logger.removeHandler(handler)

        logging.basicConfig(format="[%(asctime)s] [%(levelname)s] - %(message)s", level=logging.INFO)
        logging.StreamHandler.emit = lambda self, record: print(logging.StreamHandler.format(self, record))

    def _is_mock_request(self):
        endpoint = self.inputs.get("endpoint", self.inputs)
        return endpoint["endpointProperties"].get("isMockRequest", False)

    def _build_API_url(self, url_suffix):
        endpointProperties = self.inputs.get("endpoint", self.inputs)["endpointProperties"]
        URL = "https://" + endpointProperties["hostName"] + "/api/" + endpointProperties["appID"] + url_suffix
        logging.info(f"phpIPAM URL: {URL}")
        return URL

    def _get_auth_token(self, auth_credentials, cert):

        if self.inputs.get("endpoint",self.inputs)["endpointProperties"]["authType"] == "token":
            return self.inputs.get("endpoint",self.inputs)["endpointProperties"]["tokenKey"]

        username = auth_credentials["privateKeyId"]
        password = auth_credentials["privateKey"]

        logging.info(f"Getting phpIPAM Auth Token for {username}")

        URL = self._build_API_url("/user")

        response = self._API_post(URL, cert, {'Content-Type': 'application/json'}, {}, (username,password))
        #print(response.json()["data"]["token"])

        if response.status_code == 200:
            return str(response.json()["data"]["token"])
        elif response.status_code == 401:
            logging.error(f"Invalid credentials error: {str(response.content)}")
            raise Exception(f"Invalid credentials error: {str(response.content)}")

    def _API_get(self, URL, cert, headers, data={}, auth=None):

        logging.info(f"Making API GET Call to {URL}")

        response = requests.get(url=URL, verify=cert, headers=headers, json=data, auth=auth)

        return response

    def _API_post(self, URL, cert, headers, data={}, auth=None):

        logging.info(f"Making API POST Call to {URL}")

        if auth is not None:
            response = requests.post(url=URL, verify=cert, headers=headers, json=data, auth=auth)
        else:
            response = requests.post(url=URL, verify=cert, headers=headers, json=data)

        return response

    def _API_patch(self, URL, cert, headers, data={}, auth=None):

        logging.info(f"Making API PATCH Call to {URL}")

        response = requests.patch(url=URL, verify=cert, headers=headers, json=data, auth=auth)

        return response

    def _API_delete(self, URL, cert, headers, data={}, auth=None):

        logging.info(f"Making API PATCH Call to {URL}")

        response = requests.delete(url=URL, verify=cert, headers=headers, json=data, auth=auth)

        return response

