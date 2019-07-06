"""
This script will initialize needed components and create the specified number
of instances, along with a master ssh key for all instances and set password
access for each instance.
The script will also create CSV file containing information about each of
the instances, including their label, ID, IP, and Password.

This script can be run from command-line as follows:
python3 demo-instances.py -n [num-instances]
To view all additional optional parameters, run
python3 demo-instances.py -h
"""
import argparse
import os
import random
import string
import subprocess
import time

from cloudbridge.factory import CloudProviderFactory, ProviderList
from cloudbridge.interfaces.resources import TrafficDirection


def main():
    parser = argparse.ArgumentParser(description='Bulk instance creation '
                                                 'with CloudBridge')

    parser.add_argument('-n', '--number', help='Number of instances to create',
                        required=True, type=int, metavar='[integer]')
    parser.add_argument('-i', '--image',
                        help='ID of image to use for the  instances. Will '
                             'default to Ubuntu 18.04 on JetStream',
                        required=False,
                        type=str,
                        default='516b3611-ff7d-4eb3-bca2-80e1aef034dd',
                        metavar='[image-id]')
    parser.add_argument('-l', '--label',
                        help='Label prefix that will be used for all '
                             'resources. Will default to "bulk-cb"',
                        required=False,
                        type=str,
                        default='bulk-cb',
                        metavar = '[my-prefix]')
    parser.add_argument('-s', '--start',
                        help='Number at which to start numbering instances. '
                             'Will default to 0',
                        required=False,
                        type=int,
                        default=0,
                        metavar='[integer]')
    parser.add_argument('-t', '--vm-type',
                        help='Name of the VM Type to use. Will use '
                             '"m1.small" by default for JetStream.',
                        required=False,
                        type=str,
                        default='m1.small',
                        metavar='[vm_type_name]')
    parser.add_argument('-o', '--output',
                        help='Path to output file for instance and password '
                             'information. By default will output to '
                             '"info.txt" in the current directory',
                        required=False,
                        type=str,
                        default='info.txt',
                        metavar='[/path/to/file]')
    parser.add_argument('-p', '--provider',
                        help='Provider to be used by CloudBridge',
                        required=False,
                        type=str,
                        choices=['openstack','azure','aws','gce'],
                        default='openstack')
    parser.add_argument('--network',
                        help='Network ID to be used by CloudBridge',
                        required=False,
                        type=str,
                        metavar='[net_id]',
                        default='')
    parser.add_argument('--subnet',
                        help='Subnet ID to be used by CloudBridge',
                        required=False,
                        type=str,
                        metavar='[sn_id]',
                        default='')
    parser.add_argument('--firewall',
                        help='Firewall ID to be used by CloudBridge',
                        required=False,
                        type=str,
                        metavar='[fw_id]',
                        default='')
    parser.add_argument('--router',
                        help='Router ID to be used by CloudBridge',
                        required=False,
                        type=str,
                        metavar='[r_id]',
                        default='')
    parser.add_argument('--stagger',
                        help='Number of instances to create before starting '
                             'to set-up ssh password access. Example: if '
                             '--stagger is 1 (default), it will boot instance '
                             '#1, boot instance #2, set-up password access '
                             'for instance #1, boot instance #3, set-up '
                             'instance #2, etc...',
                        required=False,
                        type=int,
                        metavar='[integer]',
                        default=1)
    parser.add_argument('--delay',
                        help="Number of seconds to wait before setting up "
                             "SSH access. This is needed if the VMs are not "
                             "ready for SSH access right after they're "
                             "booted. Will default to 0",
                        required=False,
                        type=int,
                        metavar='[integer]',
                        default=0)


    args = vars(parser.parse_args())
    image_id = args['image']
    prefix = args['label']
    start = args['start']
    n = args['number']
    vm_type_name = args['vm_type']
    info_file_path = args['output']
    prov = args['provider']
    stagger = args['stagger']
    delay = args['delay']

    # Each instance will have a randomly generated password of this size
    pw_size = 8  # chars
    # And will use this pool of characters to generate it
    pw_contents = string.ascii_lowercase
    pw_contents += string.ascii_uppercase
    pw_contents += string.digits

    # ADD CONFIGURATION HERE IF YOU DO NOT WISH TO USE SYSTEM-LEVEL CONF
    # Using a configuration file or environment variables by default.
    config = {}
    if prov == "azure":
        prov = ProviderList.AZURE
    elif prov == "aws":
        prov = ProviderList.AWS
    elif prov == "openstack":
        prov = ProviderList.OPENSTACK
    elif prov == "gce":
        prov = ProviderList.GCE

    provider = _init_provider(config, prov)
    # This Key Pair can be used for all instances
    # The private portion will be created in the current directory with the
    # same name as the Key Pair
    master_kp, kp_file = _init_master_kp(prefix, provider)

    net = args['network']
    if not net:
        net = _init_network(prefix, provider)
    else:
        net = provider.networking.networks.get(net)

    print("Using network: " + str(net))

    sn = args['subnet']
    if not sn:
        sn = _init_subnet(prefix, provider, net)
    else:
        sn = provider.networking.subnets.get(sn)

    print("Using subnet: " + str(sn))

    router = args['router']
    if not router:
        router, gw = _init_router_and_gateway(prefix, provider, sn)
    else:
        router = provider.networking.routers.get(router)
        gw = net.gateways.get_or_create()

    print("Using router: " + str(router))
    print("Using gateway: " + str(gw))

    fw = args['firewall']
    if not fw:
        fw = _init_firewall(prefix, provider, net)
    else:
        fw = provider.security.vm_firewalls.get(fw)

    print("Using firewall: " + str(fw))

    vm_type = get_vm_type_by_name(provider, vm_type_name)
    image = get_image(provider, image_id)

    create_instances(prefix, provider, n, start, sn, gw, fw,
                     master_kp, vm_type, image, kp_file,
                     pw_contents, pw_size, info_file_path,
                     stagger, delay)


def _init_provider(config, provider):
    # Connecting to provider and generating keypair for all instances
    prov = CloudProviderFactory().create_provider(provider,
                                                  config)
    return prov


def _init_master_kp(prefix, provider):
    kp_name = prefix + '-masterkey'
    kp_file = kp_name + '.pem'

    kp_find = provider.security.key_pairs.find(name=kp_name)
    if len(kp_find) > 0:
        kp = kp_find[0]

    else:
        print("KeyPair not found. Creating new Keypair\n")
        kp = provider.security.key_pairs.create(kp_name)

        # Some software (eg: paramiko) require that RSA be specified
        key_contents = kp.material
        if 'RSA PRIVATE' not in key_contents:
            key_contents = key_contents.replace('PRIVATE KEY',
                                                'RSA PRIVATE KEY')

        # Writing private portion of key to .pem file
        with open(kp_file, 'w') as f:
            f.write(key_contents)
        os.chmod(kp_file, 0o400)
    print("Private key saved in: " + str(kp_file))

    print("Using Key Pair: " + str(kp))
    return kp, kp_file


def generate_password(size, characters):
    return ''.join(random.choice(characters) for i in range(size))


def _init_network(prefix, provider):
    # Getting already existing network or creating a new one
    net_label = prefix + '-network'
    net_find = provider.networking.networks.find(label=net_label)
    if len(net_find) > 0:
        net = net_find[0]
    else:
        net = provider.networking.networks.create(
            label=net_label, cidr_block='10.0.0.0/16')
    return net


def _init_subnet(prefix, provider, network):
    # Getting already existing subnet or creating a new one
    sn_label = prefix + '-subnet'
    sn_find = provider.networking.subnets.find(label=sn_label)
    if len(sn_find) > 0:
        sn = sn_find[0]
    else:
        sn = provider.networking.subnets.create(label=sn_label,
                                                network=network,
                                                cidr_block='10.0.0.0/24',
                                                zone=provider.region_name)
    return sn


def _init_router_and_gateway(prefix, provider, subnet):
    # Getting already existing router or creating a new one
    router_label = prefix + '-router'
    network = subnet.network
    router_find = provider.networking.routers.find(label=router_label)
    if len(router_find) > 0:
        router = router_find[0]
    else:
        router = provider.networking.routers.create(network=network,
                                                    label=router_label)
        router.attach_subnet(subnet)

    gateway = network.gateways.get_or_create_inet_gateway()
    router.attach_gateway(gateway)
    return router, gateway


def _init_firewall(prefix, provider, network):
    # Getting already existing firewall or creating a new one
    fw_label = prefix + '-firewall'
    fw_find = provider.security.vm_firewalls.find(label=fw_label)
    if len(fw_find) > 0:
        fw = fw_find[0]
    else:
        fw = provider.security.vm_firewalls.create(fw_label, network,
                                                   'Bulk Instances')
        # Opening up the appropriate ports
        fw.rules.create(TrafficDirection.INBOUND, 'tcp', 220, 220,
                        '0.0.0.0/0')
        fw.rules.create(TrafficDirection.INBOUND, 'tcp', 20, 22,
                        '0.0.0.0/0')
        fw.rules.create(TrafficDirection.INBOUND, 'tcp', 80, 80,
                        '0.0.0.0/0')
        fw.rules.create(TrafficDirection.INBOUND, 'tcp', 8080, 8080,
                        '0.0.0.0/0')
        fw.rules.create(TrafficDirection.INBOUND, 'tcp', 30000,
                        30100, '0.0.0.0/0')
    return fw


def get_image(provider, image_id):
    img = provider.compute.images.get(image_id)
    print("Using image: " + str(img))
    return img


def get_vm_type_by_name(provider, vm_type_name):
    for t in provider.compute.vm_types:
        if t.name == vm_type_name:
            print("Using VM Type: " + str(t))
            return t


def _create_instance(prefix, provider, i, subnet, gateway, firewall,
                     key_pair, vm_type, image):
    """
    Create a single instance
    """
    print('\nCreating Instance #' + str(i))
    curr_label = prefix + "-inst-" + str(i)
    inst = provider.compute.instances.create(
        label=curr_label, image=image, vm_type=vm_type,
        subnet=subnet, key_pair=key_pair, vm_firewalls=[firewall],
        zone=provider.region_name)
    inst.wait_till_ready()  # This is a blocking call

    # Get an available or create a floating IP, then attach it and print
    # the public ip
    fip = None
    for each_fip in gateway.floating_ips:
        if not each_fip.in_use:
            fip = each_fip
            break

    if not fip:
        fip = gateway.floating_ips.create()
        print("Created new IP: " + fip.public_ip)
    else:
        print("Using existing IP: " + fip.public_ip)

    inst.add_floating_ip(fip)
    inst.refresh()
    try:
        inst_ip = str(inst.public_ips[0])
    # Sometimes the refresh above does not properly refresh the public IPs
    # resulting in no attached IPs and an IndexError
    # Catch this exception if it happens and retry once after waiting a few
    # seconds
    except IndexError:
        # Arbitrary wait
        time.sleep(10)
        inst.refresh()
        inst_ip = str(inst.public_ips[0])
    print('Instance Public IP: ' + inst_ip)
    print('Instance "' + curr_label + '" created.')

    return curr_label, inst.id, inst_ip


def set_password_access(ip, desired_password, kp_file_path):
    # Generate the instance-specific password
    subprocess.run([
        'ssh', '-o', 'StrictHostKeyChecking=no', '-o',
        'UserKnownHostsFile=/dev/null', '-i', kp_file_path,
        'ubuntu@' + ip, 'sed -e \
            s/"PasswordAuthentication no"/"PasswordAuthentication yes"/g \
            /etc/ssh/sshd_config > gcc-temp.txt \
            && sudo mv gcc-temp.txt /etc/ssh/sshd_config \
            && sudo service ssh restart\
            && echo "ubuntu:' + desired_password + '" | sudo chpasswd \
            && exit'])
    # && sudo pip install -U cryptography\
    # && sudo rm -rf /usr/lib/python2.7/dist-packages/OpenSSL\
    # && sudo rm -rf /usr/lib/python2.7/dist-packages/\
    # pyOpenSSL-0.15.1.egg-info\
    # && sudo pip install pyopenssl\
    # The cryprography and openssl fixes are needed to run the demo at:
    # https://github.com/galaxyproject/dagobah-training/blob/2018-gccbosc/sessions/14-ansible/ex2-galaxy-ansible.md
    # in June 2018
    print("Password changed for instance with ip '{}'".format(ip))
    return True


def append_info_to_file(info_file_path, label, id, ip, password):
    table = '{},{},{},{}\n'
    with open(info_file_path, 'a') as info:
        info.write(table.format(label, id, ip, password))


def create_instances(prefix, provider, n, start, subnet, gateway, firewall,
                     key_pair, vm_type, image, kp_file_path,
                     pw_contents, pw_size, info_file_path,
                     stagger, delay):
    """
    Creates the indicated number of instances after initialization.
    """
    init_message = "Creating {} instances, numbered starting from " \
                   "index {}, and labeled with the prefix '{}'."
    print(init_message.format(n, start, prefix))

    prev_info = []

    for i in range(start, n + start):
        label, ins_id, ins_ip = _create_instance(prefix, provider, i, subnet,
                                                 gateway, firewall, key_pair,
                                                 vm_type, image)
        prev_info.append((label, ins_id, ins_ip))

        if len(prev_info) > stagger:
            prev_label, prev_id, prev_ip = prev_info.pop(0)
            pw = generate_password(pw_size, pw_contents)
            if delay:
                time.sleep(delay)
            set_password_access(prev_ip, pw, kp_file_path)
            append_info_to_file(info_file_path, prev_label, prev_id,
                                prev_ip, pw)
    while prev_info:
        prev_label, prev_id, prev_ip = prev_info.pop(0)
        pw = generate_password(pw_size, pw_contents)
        if delay:
            time.sleep(delay)
        set_password_access(prev_ip, pw, kp_file_path)
        append_info_to_file(info_file_path, prev_label, prev_id,
                            prev_ip, pw)


if __name__ == "__main__":
    main()


