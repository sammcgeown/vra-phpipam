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

        from phpipam_client import PhpIpamClient, GET, PATCH
        logging.info("Preparing phpIPAM connection")
        ipam = PhpIpamClient(
            url=inputs["endpoint"]["endpointProperties"]["hostName"],
            app_id= "vra",
            username=username,
            password=password,
            user_agent='vra-ipam', # custom user-agent header
        )

        allocation_result = []
        try:
            resource = inputs["resourceInfo"]
            for allocation in inputs["ipAllocations"]:
                allocation_result.append(allocate(resource, allocation, context, inputs["endpoint"], ipam))
        except Exception as e:
            try:
                rollback(allocation_result, ipam)
            except Exception as rollback_e:
                logging.error(f"Error during rollback of allocation result {str(allocation_result)}")
                logging.error(rollback_e)
            return build_error_response("5000", str(e))

        assert len(allocation_result) > 0
        return {
            "ipAllocations": allocation_result
        }
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return build_error_response("5000", str(e))
    finally:
        if cert is not None and type(cert) is str:
            os.unlink(cert)


def allocate(resource, allocation, context, inputs, ipam):
    last_error = None
    for range_id in allocation["ipRangeIds"]:
        logging.info(f"Allocating from range {range_id}")
        try:
          if int(allocation["size"]) == 1:
              logging.info(f"Querying for next available IP address from range {range_id}")
              owner = resource["owner"]
              description = "Allocated by vRealize Automation"
              port = int(allocation["nicIndex"])
              hostname = resource["name"]
              allocatedIp = ipam.post('/addresses/first_free/'+range_id+'/', {
                  "description": description,
                  "hostname": hostname,
                  "owner": owner,
                  "port": port
              })
              result = {
                  "ipAllocationId": allocation["id"],
                  "ipRangeId": range_id,
                  "ipVersion": "IPv4",
                  "ipAddresses": allocatedIp
              }
              return result
          else:
              # TODO: allocate continuous block of ips
              pass
          raise Exception("Not implemented")
        except Exception as e:
            last_error = e
            logging.error(f"Failed to allocate from range {range_id}: {str(e)}")
    logging.error("No more ranges. Raising last error")
    raise last_error


def rollback(allocation_result, ipam):
    for allocation in reversed(allocation_result):
        logging.info(f"Rolling back allocation {str(allocation)}")
        for allocatedIp in allocation_result["ipAddresses"]:
            logging.info("Rolling back IP allocation: "+allocatedIp)
            ipam.delete('/adresses/'+allocatedIp+'/'+allocation_result["ipRangeId"])
    return


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
