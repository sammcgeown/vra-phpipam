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
        # cert = get_cert(inputs)
        from phpipam_client import PhpIpamClient, GET, PATCH
        logging.info("Preparing phpIPAM connection")
        ipam = PhpIpamClient(
            url=inputs["endpoint"]["endpointProperties"]["hostName"],
            app_id= "vra",
            username=username,
            password=password,
            user_agent='vra-ipam', # custom user-agent header
        )
        sectionId = "3"
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


# def convert_networks(networks):
#     result = []
#     if networks is not None:
#         logging.info(f"Networks found: {len(networks)}")
#         for network in networks:
#             try:
#                 result.append(convert_network(network))
#             except Exception as e:
#                 logging.error(f"Failed to convert {network}: {e}")

#     return result


# def convert_network(network):
#     logging.info("Converting network %s", network["_ref"])
#     network_obj = ipaddress.ip_network(network["network"])
#     result = {
#         "id": network["_ref"],

#         "name": network["network"],

#         "startIPAddress": str(next(network_obj.hosts())),

#         "endIPAddress": str(ipaddress.ip_address(int(network_obj.broadcast_address) - 1)),

#         "description": network.get("comment", None),

#         "ipVersion": "IPv4",

#         "addressSpaceId": network["network_view"],

#         "subnetPrefixLength": network["network"].split("/", 1)[1],

#         "tags": convert_extattrs("network", network["extattrs"]),

#         "properties": {
#         }
#     }

#     populate_dhcp_options(network, result)

#     return result


# def convert_extattrs(type, extattrs):
#     tags = []
#     for key in extattrs:
#         tag = {
#             "key": key,
#             "value": str(extattrs[key]["value"])
#         }
#         tags.append(tag)
    
#     tag = {
#         "key": "range-type",
#         "value": type
#     }
#     tags.append(tag)
#     return tags


# def populate_dhcp_options(range_or_network, result):
#     if range_or_network.get("options") is not None:
#         for option in range_or_network["options"]:
#             if option["name"] == "routers" and option["use_option"] is True:
#                 result["gatewayAddress"] = option["value"].split(",")[0]
#             elif option["name"] == "domain-name" and option["use_option"] is True:
#                 result["domain"] = option["value"]   
#             elif option["name"] == "domain-name-servers" and option["use_option"] is True:
#                 result["dnsServerAddresses"] = option["value"].split(",")              
#             elif option["name"] == "domain-search": # This is custom DHCP option that does not have 'use_option' to distinguish whether it's inherited
#                 result["dnsSearchDomains"] = list(map(lambda with_doubly_quotes: with_doubly_quotes[1:-1], option["value"].split(",")))

#     network = range_or_network
#     if result['id'].startswith('range/'): # In case this is a DHCP-enabled range (has member assigned) then obtain its network and recursively traverse the DHCP option hierarchy
#         network = conn.get_object('network',
#                               payload = {'network_view': range_or_network["network_view"], 'network': range_or_network['network']},
#                               paging = False,
#                               return_fields=['default','extattrs','options','comment', 'members', 'network_container'])[0]

#     if result.get('gatewayAddress', None) is None:
#         dhcp_option = get_dhcp_option_from_parent('routers', network)
#         if dhcp_option is not None:
#             result['gatewayAddress'] = dhcp_option.split(",")[0]

#     if result.get('domain', None) is None:
#         dhcp_option = get_dhcp_option_from_parent('domain-name', network)
#         if dhcp_option is not None:
#             result['domain'] = dhcp_option

#     if result.get('dnsServerAddresses', None) is None:
#         dhcp_option = get_dhcp_option_from_parent('domain-name-servers', network)
#         if dhcp_option is not None:
#             result['dnsServerAddresses'] = dhcp_option.split(",")

#     if result.get('dnsSearchDomains', None) is None:
#         dhcp_option = get_dhcp_option_from_parent('domain-search', network)
#         if dhcp_option is not None:
#             result['dnsSearchDomains'] = list(map(lambda with_doubly_quotes: with_doubly_quotes[1:-1], dhcp_option.split(",")))

#     return result


# ref_cache = {}


# def get_dhcp_option_from_parent(option_name, network_or_container, members = None):

#     if members is None: # means this is a network object.
#         logging.info(f"DHCP option {option_name} for {network_or_container['_ref']} is None. Fetching it from parent recursively...")
#         members = network_or_container["members"]

#     if network_or_container.get("options", None) is not None:
#         for option in network_or_container["options"]:
#             if option["name"] == option_name and option.get("use_option", True) is True:
#                 logging.info(f"DHCP option {option_name} found in {network_or_container}.")
#                 return option["value"]

#     if network_or_container['network_container'] == '/':
#         return get_dhcp_option_from_grid(option_name, members)
#     else:
#         query = {
#             'network_view': network_or_container["network_view"], 
#             'network': network_or_container['network_container']
#         }
#         key = str(query)
#         if ref_cache.get(key, None) is None:
#             logging.info(f"Querying for DHCP option {option_name} and key {key}")
#             network_or_container = conn.get_object('networkcontainer',
#                                                     query,
#                                                     return_fields=['default', 'extattrs', 'options', 'network_container'],
#                                                     max_results=1)
#             if network_or_container is None:
#                 network_or_container = {'network_container': '/', '_ref': 'Not-Found', 'comment': 'Probably user doesn\'t have permission to view this container through WAPI'}
#             else:
#                 network_or_container = network_or_container[0]
            
#             logging.info(f"Found object {network_or_container}. Caching it...")
#             ref_cache[key] = network_or_container
#         else:
#             network_or_container = ref_cache[key]

#         return get_dhcp_option_from_parent(option_name, network_or_container, members)


# def get_dhcp_option_from_grid(option_name, members):
#     if not members:
#         return None
    
#     query = {
#         'ipv4addr': members[0]['ipv4addr']
#     }
#     key = "grid-member-dhcp" + str(query)
#     if ref_cache.get(key, None) is None:
#         logging.info(f"Querying for DHCP option {option_name} and key {key}")
#         member = conn.get_object('member:dhcpproperties', query,
#                                  return_fields=['default', 'options'],
#                                  max_results=1)
#         if member is None:
#             member = {'_ref': 'Not-Found', 'comment': 'Probably user doesn\'t have permission to view this grid member through WAPI'}
#         else:
#             member = member[0]
            
#         logging.info(f"Found object {member}. Caching it...")
#         ref_cache[key] = member
#     else:
#         member = ref_cache[key]
        
#     if member.get("options", None) is not None:
#         for option in member["options"]:
#             if option["name"] == option_name and option.get("use_option", True) is True:
#                 logging.info(f"DHCP option {option_name} found in {member}.")
#                 return option["value"]

#     # Option not found in grid member. Querying the grid
#     key = "grid-dhcp"
#     if ref_cache.get(key, None) is None:
#         logging.info(f"Querying for DHCP option {option_name} and key {key}")
#         grid = conn.get_object('grid:dhcpproperties',
#                                 return_fields=['default', 'options'],
#                                 max_results=1)
                                
#         if grid is None:
#             grid = {'_ref': 'Not-Found', 'comment': 'Probably user doesn\'t have permission to view the grid through WAPI'}
#         else:
#             grid = grid[0]
            
#         logging.info(f"Found object {grid}. Caching it...")
#         ref_cache[key] = grid
#     else:
#         grid = ref_cache[key]
    
#     if grid.get("options", None) is not None:
#         for option in grid["options"]:
#             if option["name"] == option_name and option.get("use_option", True) is True:
#                 logging.info(f"DHCP option {option_name} found in {grid}.")
#                 return option["value"]
                
#     logging.info(f"DHCP option {option_name} not found.")
#     return None


# def convert_ranges(ranges):
#     result = []
#     if ranges is not None:
#         logging.info(f"Ranges found: {len(ranges)}")
#         for range in ranges:
#             try:
#                 result.append(convert_range(range))
#             except Exception as e:
#                 logging.error(f"Failed to convert {range}: {e}")

#     return result


# def convert_range(range):
#     logging.info("Converting range %s", range["_ref"])
#     result = {
#         "id": range["_ref"],

#         "name": range["start_addr"] + "-" + range["end_addr"],

#         "startIPAddress": range["start_addr"],

#         "endIPAddress": range["end_addr"],

#         "description": range.get("comment", None),

#         "ipVersion": "IPv4",

#         "addressSpaceId": range["network_view"],

#         "subnetPrefixLength": range["network"].split("/", 1)[1],

#         "tags": convert_extattrs("range", range["extattrs"]),

#         "properties": {
#         }
#     }

#     if 'member' in range:
#         populate_dhcp_options(range, result)

#     return result


# # So if we have a pageToken in the inputs, it means that this is a consecutive enumeration request.
# # The page token could be either for networks or for ranges or for both
# # In case the pageToken is for networks only, skip querying the ranges and vice versa - if it is for ranges only
# # then skip querying of the networks.
# # In case pageToken is missing it means we query all
# def get_page_token(inputs, obj_type):

#     if inputs['pagingAndSorting'].get('pageToken', None) is None:
#         return False, None

#     page_token = json.loads(inputs['pagingAndSorting']['pageToken'])

#     if obj_type is 'network':
#         page_token = page_token.get('network_next_page_id', None)
#     elif obj_type is 'range':
#         page_token = page_token.get('range_next_page_id', None)
#     else:
#         return False, None

#     skip = False
#     if page_token is None:
#         skip = True
#         logging.info(f"Next page token not found for {obj_type}s. Skipping enumeration")

#     page_token = {
#         '_page_id': page_token
#     }

#     return skip, page_token


def build_error_response(error_code, error_message):
    return {
        "error": {
            "errorCode": error_code,
            "errorMessage": error_message
        }
    }
