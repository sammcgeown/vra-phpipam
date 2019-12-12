import json
import tempfile
import os
import logging
import ipaddress
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
        #cert = get_cert(inputs)
        phpIPAMProperties = get_properties(inputs)
        appId = phpIPAMProperties["phpIPAM.appId"]
        from phpipam_client import PhpIpamClient, GET, PATCH
        logging.info("Preparing phpIPAM connection")
        ipam = PhpIpamClient(
            url=inputs["endpoint"]["endpointProperties"]["hostName"],
            app_id=appId,
            username=username,
            password=password,
            user_agent='vra-ipam', # custom user-agent header
        )

        ipDeallocations = []
        try:
            for ipDeallocation in inputs["ipDeallocations"]:
                ipDeallocations.append(deallocateIp(ipDeallocation, ipam))
        except Exception as e:
            logging.error(f"Error during deallocation: {str(e)}")
            return build_error_response("5000", str(e))
        assert len(ipDeallocations) > 0
        return {
            "ipDeallocations": ipDeallocations
        }
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return build_error_response("5000", str(e))
    finally:
        if cert is not None and type(cert) is str:
            os.unlink(cert)



def deallocateIp(ipDeallocation, ipam):
    ipToDeallocate = ipDeallocation["ipAddress"]
    logging.info(f"Removing IP allocation {str(ipToDeallocate)}")
    ipam.delete('/addresses/'+ipToDeallocate+'/'+ipDeallocation["ipRangeId"]+'/')
    return {
        "ipDeallocationId": ipDeallocation["id"]
    }


def get_auth_credentials(context, inputs):
    logging.info("Querying for auth credentials")
    auth_credentials_link = inputs["endpoint"]["authCredentialsLink"]
    auth_credentials_response = context.request(auth_credentials_link, 'GET', '')
    if auth_credentials_response["status"] == 200:
        logging.info("Credentials obtained successfully!")
        return json.loads(auth_credentials_response["content"])
    raise Exception('Failed to obtain auth credentials from {}: {}'.format(auth_credentials_link, str(auth_credentials_response)))


def build_error_response(error_code, error_message):
    return {
        "error": {
            "errorCode": error_code,
            "errorMessage": error_message
        }
    }

def get_properties(inputs):
    properties_list = inputs["endpoint"]["endpointProperties"].get("properties", [])
    properties_list = json.loads(properties_list)
    properties = {}
    for prop in properties_list:
        properties[prop["prop_key"]] = prop["prop_value"]
    return properties