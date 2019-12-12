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
        phpIPAMProperties = get_properties(inputs)
        appId = phpIPAMProperties["phpIPAM.appId"]
        # cert = get_cert(inputs)
        from phpipam_client import PhpIpamClient, GET, PATCH
        logging.info("Preparing phpIPAM connection")
        ipam = PhpIpamClient(
            url=inputs["endpoint"]["endpointProperties"]["hostName"],
            app_id= appId,
            username=username,
            password=password,
            user_agent='vra-ipam', # custom user-agent header
        )
        sectionId = getSectionId(phpIPAMProperties["phpIPAM.sectionName"],ipam)
        # sectionId = "3"
        subnets = ipam.get('/sections/'+sectionId+'/subnets')
        ipRanges = []
        for subnet in subnets:
            subnetPrefixLength = subnet["mask"]
            cidr = subnet["subnet"]+"/"+subnetPrefixLength
            network = ipaddress.IPv4Network(cidr)
            startIpAddress, endIpAddress = str(network[1]), str(network[-2])
            # Build ipRange Object
            ipRange = {}
            ipRange["id"] = subnet["id"]
            ipRange["name"] = cidr
            ipRange["description"] = subnet["description"]
            ipRange["startIPAddress"] = startIpAddress
            ipRange["endIPAddress"] = endIpAddress
            ipRange["ipVersion"] = 'IPv4'
            if "gatewayId" in subnet:
                gatewayIp = ipam.get("/addresses/"+subnet["gatewayId"]+"/")
                ipRange["gatewayAddress"] = gatewayIp["ip"]
            if "nameservers" in subnet:
                ipRange["dnsServerAddresses"] = subnet["nameservers"]["namesrv1"].split(';')
            ipRange["subnetPrefixLength"] = subnetPrefixLength
            #ipRange["addressSpaceId"] = addressSpaceId
            #ipRange["domain"] = None
            #ipRange["dnsSearchDomains"] = None
            #ipRange["properties"] = None
            #ipRange["tags"] = None
            #logging.info(subnet["id"], cidr, subnet["description"], startIpAddress, endIpAddress, 'IPv4', addressSpaceId, gatewayAddress, subnetPrefixLength, dnsServerAddresses)
            ipRanges.append(ipRange)
        #logging.info(ipRanges)
        result = {
            "ipRanges": ipRanges
        }
        return result
    except Exception as e:
        return build_error_response("5000", str(e))
    finally:
        if cert is not None and type(cert) is str:
            os.unlink(cert)

def getSectionId(sectionName,ipam):
    logging.info("Getting section ID for "+sectionName)
    section = ipam.get('/sections/'+sectionName+'/')
    if section["id"] is not None:
        return section["id"]
    else:
        raise Exception('Unable to find section named '+sectionName)

def get_auth_credentials(context, inputs):
    logging.info("Querying for auth credentials")
    auth_credentials_link = inputs["endpoint"]["authCredentialsLink"]
    auth_credentials_response = context.request(auth_credentials_link, 'GET', '')
    if auth_credentials_response["status"] == 200:
        logging.info("Credentials obtained successfully!")
        return json.loads(auth_credentials_response["content"])

    raise Exception('Failed to obtain auth credentials from {}: {}'.format(auth_credentials_link, str(auth_credentials_response)))

# def get_cert(inputs):
#     properties = get_properties(inputs)
#     certificate = inputs["endpoint"]["endpointProperties"].get("certificate", None)
#     if certificate is not None:
#         cert = tempfile.NamedTemporaryFile(mode='w', delete=False)
#         cert.write(certificate)
#         cert.close()
#         return cert.name
#     elif properties.get("Infoblox.IPAM.DisableCertificateCheck", "false").lower() == "true":
#         logging.info("Disabling certificate check")
#         return False
#     else:
#         return True


def get_properties(inputs):
    properties_list = inputs["endpoint"]["endpointProperties"].get("properties", [])
    properties_list = json.loads(properties_list)
    properties = {}
    for prop in properties_list:
        properties[prop["prop_key"]] = prop["prop_value"]
    return properties

def build_error_response(error_code, error_message):
    return {
        "error": {
            "errorCode": error_code,
            "errorMessage": error_message
        }
    }
