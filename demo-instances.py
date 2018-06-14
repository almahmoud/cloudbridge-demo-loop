'''
This script will initialize needed components and create the specified number
of instances, along with a master ssh key for all instances and a personal
ssh keypair for each instance. The public portion of the instance-specific
keypair is already added to the authorized_keys file in each instance.
The script will store all public and private portions of keys as files in a
keys/ directory, as well as create a CSV file containing all the information.

This script can be run from command-line as follows:
python3 demo-instances.py -n [num-instances]
Additional parameters include:
-p prefix : specify a new prefix for all components and instances
'''

from cloudbridge.cloud.factory import CloudProviderFactory, ProviderList
from cloudbridge.cloud.interfaces import resources
import os
import sys
import subprocess
import random
import string
import time


args = sys.argv

# Using a configuration file or environment variables by default.
# Specify configuration dictionary here if using it instead
config = {}

# Each instance will have a randomly generated password of this size
pw_size = 8  # chars
pw_contents = string.ascii_lowercase + string.ascii_uppercase + string.digits

# Create the keys directory if it is not already created
keys_dir = 'keys/'
if not os.path.exists(keys_dir):
    os.makedirs(keys_dir)

# Ubuntu 16.04.03 @ Jetstream
image_id = 'acb53109-941f-4593-9bf8-4a53cb9e0739'

# Prefix used for naming all networking components and files
prefix = '2018-gcc-training-'

# The universal private key will be created in a file with this name
kp_name = prefix + 'masterkey'
kp_file = kp_name + '.pem'

# Connecting to provider and generating keypair for all instances
prov = CloudProviderFactory().create_provider(ProviderList.OPENSTACK, config)

kp_find = prov.security.key_pairs.find(name=kp_name)
if len(kp_find) > 0:
    kp = kp_find[0]

else:
    kp = prov.security.key_pairs.create(kp_name)

    # Some software (eg: paramiko) require that RSA be specified
    key_contents = kp.material
    if 'RSA PRIVATE' not in key_contents:
        key_contents = key_contents.replace('PRIVATE KEY', 'RSA PRIVATE KEY')

    # Writing private portion of key to .pem file
    with open(kp_file, 'w') as f:
        f.write(key_contents)
    os.chmod(kp_file, 0o400)

# Getting already existing network or creating a new one
net_name = prefix + 'network'
net_find = prov.networking.networks.find(name=net_name)
if len(net_find) > 0:
    net = net_find[0]
else:
    net = prov.networking.networks.create(
        name=net_name, cidr_block='10.0.0.0/16')

# Getting already existing subnet or creating a new one
sn_name = prefix + 'subnet'
sn_find = prov.networking.subnets.find(name=sn_name)
if len(sn_find) > 0:
    sn = sn_find[0]
else:
    sn = net.create_subnet(name=sn_name, cidr_block='10.0.0.0/25')

# Getting already existing router or creating a new one
router_name = prefix + 'router'
router_find = prov.networking.routers.find(name=router_name)
if len(router_find) > 0:
    router = router_find[0]
else:
    router = prov.networking.routers.create(network=net, name=router_name)
    router.attach_subnet(sn)

gateway = net.gateways.get_or_create_inet_gateway(prefix + 'gateway')
router.attach_gateway(gateway)

# Getting already existing firewall or creating a new one
fw_name = prefix + 'firewall'
fw_find = prov.security.vm_firewalls.find(name=fw_name)
if len(fw_find) > 0:
    fw = fw_find[0]
else:
    fw = prov.security.vm_firewalls.create(fw_name, 'Instances for demo', net.id)
    # Opening up the appropriate ports
    fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 220, 220, '0.0.0.0/0')
    fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 21, 21, '0.0.0.0/0')
    fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 22, 22, '0.0.0.0/0')
    fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 80, 80, '0.0.0.0/0')
    fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 8080, 8080, '0.0.0.0/0')
    fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 30000, 30100, '0.0.0.0/0')

# Get image using the hardcoded ID
img = prov.compute.images.get(image_id)

# Get m1.small VM type (hardcoded), and print to make sure it is the desired one
vm_type = [t for t in prov.compute.vm_types][4]
print('VM Type used: ')
print(vm_type)


def create_instances(n):
    '''
    Creates the indicated number of instances after initialization.
    '''
    inst_names = []
    inst_ids = []
    inst_ips = []

    for i in range(n):
        print('\nCreating Instance #' + str(i))
        curr_name = prefix + 'key-'+str(i)
        inst = prov.compute.instances.create(
            name=curr_name, image=img, vm_type=vm_type,
            subnet=sn, key_pair=kp, vm_firewalls=[fw])
        inst.wait_till_ready()  # This is a blocking call

        # Track instances for immediate clean-up if requested
        inst_names.append(curr_name)
        inst_ids.append(inst.id)

        # Get an available or create a floating IP, then attach it and print
        # the public ip
        fip = None
        for each_fip in gateway.floating_ips.list():
            if not each_fip.in_use:
                fip = each_fip
                break

        if fip is None:
            fip = gateway.floating_ips.create()

        inst.add_floating_ip(fip)
        inst.refresh()
        inst_ip = str(inst.public_ips[0])
        print('Instance Public IP: ' + inst_ip)

        inst_ips.append(inst_ip)

        print('Instance #' + str(i) + ' created.')

    print(str(n) + ' instances were successfully created.')
    return inst_names, inst_ids, inst_ips


def password_access(ips):
    inst_passws = []
    time.sleep(30)
    for each_ip in ips:
        # Generate the instance-specific password
        inst_pass = ''.join(random.choice(pw_contents) for i in range(pw_size))
        subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 
                        'UserKnownHostsFile=/dev/null', '-i', kp_file,
                        'ubuntu@' + each_ip, 'sed -e \
                        s/"PasswordAuthentication no"/"PasswordAuthentication yes"/g \
                        /etc/ssh/sshd_config > gcc-temp.txt \
                        && sudo mv gcc-temp.txt /etc/ssh/sshd_config\
                        && sudo service ssh restart\
                        && echo "ubuntu:' + inst_pass + '" | sudo chpasswd'])
        inst_passws.append(inst_pass)
    return inst_passws


if '-n' not in args:
    print('ERROR: The number of instances to create must be specified using the \
          "-n [int]"" argument.')

else:
    n = args.index('-n') + 1
    names, ids, ips = create_instances(int(args[n]))
    pws = password_access(ips)
    table = '{},{},{},{}\n'
    with open('info.txt', 'w') as info:
        for i in range(len(names)):
            info.write(table.format(names[i], ids[i], ips[i], pws[i]))
