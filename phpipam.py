import json
import tempfile
import os
import logging
import phpipam_client
from phpipam_client import PhpIpamClient, GET, PATCH


ipam = PhpIpamClient(
    url='http://phpipam.definit.local',
    app_id='vra',
    username='admin',
    password='b77iofI!#wVhe/IeG^yDO~MVO$w^T1aYeD2',
    user_agent='vrealizeautomation', # custom user-agent header
)

# read object
print(ipam.get('/subnets/8/'))

# # create object
# ipam.post('/sections/', {
#     'description': 'example',
# })

# # update object
# ipam.patch('/sections/1/', {
#     'description': 'example',
# })

# # delete object
# ipam.delete('/sections/1/')

# # read object
# ipam.query('/sections/', method=GET)

# # update object
# ipam.query('/sections/1/', method=PATCH, data={
#     'description': 'example',
# })