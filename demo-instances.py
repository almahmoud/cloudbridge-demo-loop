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
-c : clean-up all instances and resources after boot
'''

from cloudbridge.cloud.factory import CloudProviderFactory, ProviderList
from cloudbridge.cloud.interfaces import resources
import os
import sys
import subprocess
import time

args = sys.argv

# Using a configuration file or environment variables by default.
# Specify configuration dictionary here if using it instead
config = {}

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
    sn = net.create_subnet(name=sn_name, cidr_block='10.0.0.0/28')

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

# These lists will keep track of all instances and floating ip's to clean-up if
# indicated (primarily used for last round of testing)
insts = []
fips = []


def create_instances(n):
    '''
    Creates the indicated number of instances after initialization.
    '''

    table = '{},{},{},{}\n'
    lines = []

    for i in range(n):
        print('\nCreating Instance #' + str(i))
        curr_name = prefix + 'key-'+str(i)
        inst = prov.compute.instances.create(
            name=curr_name, image=img, vm_type=vm_type,
            subnet=sn, key_pair=kp, vm_firewalls=[fw])
        inst.wait_till_ready()  # This is a blocking call

        # Track instances for immediate clean-up if requested
        insts.append(inst)

        # Get an available or create a floating IP, then attach it and print
        # the public ip
        fip = None
        for each_fip in gateway.floating_ips.list():
            if not each_fip.in_use:
                fip = each_fip
                break

        if fip is None:
            fip = gateway.floating_ips.create()
        fips.append(fip)

        inst.add_floating_ip(fip)
        inst.refresh()
        inst_ip = str(inst.public_ips[0])
        print('Instance Public IP: ' + inst_ip)

        print('Creating instance-specific keypair')

        # Generate the instance-specific RSA keypair
        subprocess.run(['ssh-keygen', '-t', 'rsa', '-f', curr_name, '-N', ''])

        # Read private portion of the key, to add to list and spreadsheet
        with open(curr_name, 'r') as priv:
            priv_key_cont = priv.read()

        # Add .pem extension to private key and place it in the keys/ directory
        os.rename(curr_name, keys_dir + curr_name + '.pem')

        pub_key = curr_name + '.pub'

        # Wait for the instance to be ready before SCP-ing
        inst.wait_till_ready()  # This is a blocking call
        time.sleep(10)

        # Get the autorized_keys file from remote instance, then append the
        # instance-specific public key, then send back to the remote instance
        subprocess.run(['scp', '-o', 'StrictHostKeyChecking=no',
                        '-o', 'UserKnownHostsFile=/dev/null', '-i', kp_file,
                        'ubuntu@' + inst_ip + ':~/.ssh/authorized_keys',
                        'authorized_keys_' + curr_name])

        with open('authorized_keys_' + curr_name, 'a') as auth_k:
            with open(pub_key, 'r') as pub_k:
                auth_k.write('\n')
                auth_k.writelines(pub_k.readlines())

        subprocess.run(['scp', '-o', 'StrictHostKeyChecking=no',
                        '-o', 'UserKnownHostsFile=/dev/null', '-i', kp_file,
                        'authorized_keys_' + curr_name,
                        'ubuntu@' + inst_ip + ':~/.ssh/authorized_keys'])

        # Remove local copy after sending it back
        os.remove('authorized_keys_' + curr_name)

        # Move public key to keys/ directory after appending it to instance
        os.rename(pub_key, keys_dir + pub_key)

        print('Done with Instance #' + str(i))

        lines.append(table.format(curr_name, str(inst.id), inst_ip, priv_key_cont))

    with open('log.txt', 'w') as log_file:
        log_file.writelines(lines)


def cleanup():
    '''
    Will perform a quick cleanup when running the script just for testing
    '''
    print('Cleaning everything up')
    for each_inst in insts:
        each_inst.delete()
        each_inst.wait_for(
            [resources.InstanceState.DELETED, resources.InstanceState.UNKNOWN],
            terminal_states=[resources.InstanceState.ERROR])  # Blocking call
    for each_fip in fips:
        each_fip.delete()
    fw.delete()
    kp.delete()
    os.remove(kp_name + '.pem')
    for each_key in os.listdir(keys_dir):
        path = os.path.join(keys_dir, each_key)
        if os.path.isfile(path):
            os.unlink(path)
    router.detach_gateway(gateway)
    router.detach_subnet(sn)
    gateway.delete()
    router.delete()
    sn.delete()
    net.delete()


if '-n' not in args:
    print('ERROR: The number of instances to create must be specified using the \
          "-n [int]"" argument.')

else:
    n = args.index('-n') + 1
    if '-c' in args:
        try:
            create_instances(int(args[n]))
        finally:
            cleanup()
    else:
        create_instances(int(args[n]))
