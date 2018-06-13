from cloudbridge.cloud.factory import CloudProviderFactory, ProviderList
from cloudbridge.cloud.interfaces import resources
import os
import sys
import subprocess
import time

# Ubuntu 14.04.03 @ Jetstream
image_id = '465ece5e-8501-48ad-8794-b1eb65807293'

# Prefix used for naming all networking components and files
prefix = 'am-demo-'

# The universal private key will be created in a file with this name
kp_name = prefix + 'masterkey'
kp_file = kp_name + ".pem"

# Using a configuration file or environment variables by default.
# Specify configuration dictionary here if using it instead
config = {}

# Connecting to provider and generating keypair for all instances
prov = CloudProviderFactory().create_provider(ProviderList.OPENSTACK, config)
kp = prov.security.key_pairs.create(kp_name)

# Some software (eg: paramiko) require that RSA be specified
key_contents = kp.material
if "RSA PRIVATE" not in key_contents:
    key_contents = key_contents.replace("PRIVATE KEY", "RSA PRIVATE KEY")

# Writing private portion of key to .pem file
with open(kp_file, 'w') as f:
    f.write(key_contents)
os.chmod(kp_file, 0o400)

# Initiating network, subnet, router, and firewall
net = prov.networking.networks.create(
    name=prefix + 'network', cidr_block='10.0.0.0/16')
sn = net.create_subnet(name=prefix + 'subnet', cidr_block='10.0.0.0/28')
router = prov.networking.routers.create(network=net, name=prefix + 'router')
router.attach_subnet(sn)
gateway = net.gateways.get_or_create_inet_gateway(prefix + 'gateway')
router.attach_gateway(gateway)
fw = prov.security.vm_firewalls.create(
    prefix + 'firewall', 'Instances for demo', net.id)

# Opening up the appropriate ports
fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 220, 220, '0.0.0.0/0')
fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 21, 21, '0.0.0.0/0')
fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 22, 22, '0.0.0.0/0')
fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 80, 80, '0.0.0.0/0')
fw.rules.create(resources.TrafficDirection.INBOUND, 'tcp', 8080, 8080, '0.0.0.0/0')


# Get image using the hardcoded ID
img = prov.compute.images.get(image_id)

# Get m1.small VM type (hardcoded), and print to make sure it is the desired one
vm_type = [t for t in prov.compute.vm_types][4]
print("VM Type used: ")
print(vm_type)

# These lists will keep track of all instances and floating ip's to clean-up if
# indicated (primarily used for last round of testing)
insts = []
fips = []


def create_instances(n):
    """
    Creates the indicated number of instances after initialization.
    """

    table = "{:20}{:40}{:20}\n"
    header = table.format("Name", "Instance ID", "Public IP")
    lines = [header]

    for i in range(n):
        print('\nCreating Instance #' + str(i))
        curr_name = prefix + 'key-'+str(i)
        inst = prov.compute.instances.create(
            name=curr_name, image=img, vm_type=vm_type,
            subnet=sn, key_pair=kp, vm_firewalls=[fw])
        inst.wait_till_ready()  # This is a blocking call

        # Track instances for immediate clean-up if requested
        insts.append(inst)

        # Create and track floating IP, then attach it nadp rint the public ip
        fip = gateway.floating_ips.create()
        fips.append(fip)

        inst.add_floating_ip(fip)
        inst.refresh()
        inst_ip = str(inst.public_ips[0])
        print('Instance Public IP: ' + inst_ip)

        print('Creating instace-specific keypair')

        # Generate the instance-specific RSA keypair
        subprocess.run(['ssh-keygen', '-t', 'rsa', '-f', curr_name, '-N', ''])
        # Add .pem extension to private key
        subprocess.run(['mv', curr_name, curr_name + '.pem'])
        pub_key = curr_name + '.pub'

        # Wait for the instance to be ready before SCP-ing
        inst.wait_till_ready()  # This is a blocking call

        # Get the autorized keys file from remote instance, then append the
        # instance-specific public key, then send back to the remote instance
        subprocess.run(['scp', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-i', kp_file, 'root@' + inst_ip + ':~/.ssh/authorized_keys', 'authorized_keys_' + curr_name])
        subprocess.run('cat ' + pub_key + ' >> authorized_keys_' + curr_name, shell=True)
        subprocess.run(['scp', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-i', kp_file, 'authorized_keys_' + curr_name, 'root@' + inst_ip + ':~/.ssh/authorized_keys'])
        # Remove local copy after sending it back
        os.remove('authorized_keys_' + curr_name)

        print('Done with Instance #' + str(i))

        lines.append(table.format(curr_name, str(inst.id), inst_ip))

    with open('log.txt', 'w') as log_file:
        log_file.writelines(lines)


def cleanup():
    """
    Will perform a quick cleanup when running the script just for testing
    """
    for each_inst in insts:
        each_inst.delete()
        each_inst.wait_for([resources.InstanceState.DELETED, resources.InstanceState.UNKNOWN],
                      terminal_states=[resources.InstanceState.ERROR])  # Blocking call
    for each_fip in fips:
        each_fip.delete()
    fw.delete()
    kp.delete()
    os.remove(kp_name + '.pem')
    router.detach_gateway(gateway)
    router.detach_subnet(sn)
    gateway.delete()
    router.delete()
    sn.delete()
    net.delete()


args = sys.argv

if "-n" not in args:
    print('ERROR: The number of instances to create must be specified using the "-n [int]" argument.')

else:
    n = args.index("-n") + 1
    create_instances(int(args[n]))

if "-c" in args:
    cleanup()
