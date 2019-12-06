import json
import tempfile
import os
import logging
import phpipam_client

def setup_logger():
    logger = logging.getLogger()
    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)

    logging.basicConfig(format="[%(asctime)s] [%(levelname)s] - %(message)s", level=logging.INFO)
    logging.StreamHandler.emit = lambda self, record: print(logging.StreamHandler.format(self, record))



def handler(context, inputs):
    global logging
    setup_logger()

    cert = None
    try:
        auth_credentials = get_auth_credentials(context, inputs)
        username = auth_credentials["privateKeyId"]
        password = auth_credentials["privateKey"]
        # cert = get_cert(inputs)
        from phpipam_client import PhpIpamClient, GET, PATCH
        #logging.info(get_properties(inputs).get("appId", False))
        ipam = PhpIpamClient(
            url=inputs["endpointProperties"]["hostName"],
            app_id= "vra",
            username=username,
            password=password,
            user_agent='vra-ipam', # custom user-agent header
        )
        logging.info(ipam.get('/sections/'))
        return {
            "message": "Validated successfully",
            "statusCode": "200"
        }
    # except ib_ex.InfobloxBadWAPICredential as e:
    #     logging.error(f"InfobloxBadWAPICredential error: {str(e)}")
    #     return build_error_response("3001", str(e))
    # except ib_ex.InfobloxConnectionError as e:
    #     logging.error(f"InfobloxConnectionError error: {str(e)}")
    #     if cert is True and ("SSLCertVerificationError" in str(e) or "CERTIFICATE_VERIFY_FAILED" in str(e) or 'certificate verify failed' in str(e)):
    #         return {
    #             "certificateInfo": {
    #                 "certificate": get_certificate(inputs["endpointProperties"]["hostName"], 443)
    #             },
    #             "error": build_error_response("3002", str(e))["error"]
    #         }
    #     return build_error_response("3000", str(e))
    except Exception as e:
        logging.error(f"Unexpected exception: {str(e)}")
        return build_error_response("5000", str(e))
    finally:
        if cert is not None and type(cert) is str:
            os.unlink(cert)




def get_auth_credentials(context, inputs):
    logging.info("Querying for auth credentials")
    auth_credentials_link = inputs["authCredentialsLink"]
    auth_credentials_response = context.request(auth_credentials_link, 'GET', '')
    if auth_credentials_response["status"] == 200:
        logging.info("Credentials obtained successfully!")
        data = auth_credentials_response["content"].decode('utf-8')
        jsonData = json.loads(data)
        return jsonData

    raise Exception('Failed to obtain auth credentials from {}: {}'.format(auth_credentials_link, str(auth_credentials_response)))


def get_cert(inputs):
    #properties = get_properties(inputs)
    certificate = inputs["endpointProperties"].get("certificate", None)
    if certificate is not None:
        cert = tempfile.NamedTemporaryFile(mode='w', delete=False)
        cert.write(certificate)
        cert.close()
        return cert.name
    # elif properties.get("Infoblox.IPAM.DisableCertificateCheck", "false").lower() == "true":
    #     logging.info("Disabling certificate check")
    #     return False
    else:
        return True


def get_certificate(hostname, port):

    logging.info(f"Fetching certificate of {hostname}")
    import ssl
    import idna
    from socket import socket
    from OpenSSL import SSL
    from OpenSSL import crypto

    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    # peername = sock.getpeername()
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

    sock_ssl.close()
    sock.close()

    return sb

def build_error_response(error_code, error_message):
    return {
        "error": {
            "errorCode": error_code,
            "errorMessage": error_message
        }
    }

def get_properties(inputs):
    properties_list = inputs["endpointProperties"].get("properties", [])
    properties_list = json.loads(properties_list)
    properties = {}
    for prop in properties_list:
        properties[prop["prop_key"]] = prop["prop_value"]
    
    return properties

