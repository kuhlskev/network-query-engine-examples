#!/usr/bin/env python

"""Finds ips that are applied to multiple interfaces within a VRF."""

from forward_nqe_client import FwdApi, printTable, formatIpAddr
from collections import defaultdict
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument(
    "url",
    help="The URL of a Forward Networks instance, e.g. https://fwd.app.")
parser.add_argument(
    "username",
    help="The username of an account on the above-specified "
         "Forward Networks instance.")
parser.add_argument(
    "password",
    help="The password of an account on the above-specified "
         "Forward Networks instance.")
parser.add_argument(
    "snapshotId",
    help="The snapshotId of a snapshot on the above-specified "
         "Forward Networks instance.")
parser.add_argument(
    "--verify",
    help="Whether to verify the certificate on the instance "
         "(e.g. True or False)",
    action="store_true")
args = parser.parse_args()

# API to query Forward NQE API
api = FwdApi(args.url, (args.username, args.password), args.verify)

# Query to get device interface and VRF data.

query = '''
{
  devices {
    name
    networkInstances {
      name
      interfaces {
        subIface {
          adminStatus
          operStatus
          name
          ipv4 {
              addresses {
                ip
                prefixLength
              }
              fhrpAddresses {
                ip
                prefixLength
              }
            }
        }
        iface {
          name
          adminStatus
          operStatus
          interfaceType
          routedVlan {
            ipv4 {
              addresses {
                ip
                prefixLength
              }
              fhrpAddresses {
                ip
                prefixLength
              }
            }
          }
          bridge {
            ipv4 {
              addresses {
                ip
                prefixLength
              }
              fhrpAddresses {
                ip
                prefixLength
              }
            }
          }
          tunnel {
            ipv4 {
              addresses {
                ip
                prefixLength
              }
              fhrpAddresses {
                ip
                prefixLength
              }
            }
          }
        }
      }
    }
  }
}'''

# Query the API
dataset = api.query(args.snapshotId, query)

# Violations are those (vrf, subnet) pairs that are assigned to multiple
# distinct interfaces on a vrf. To compute this, we do the following:
#  (1) Get the IP addresses for interface
#  (2) Build a map from IP address to the the set of interfaces where it is
#      assigned by going over each vrf, getting its interfaces, and then
#      (using (1)) get its ip addresses and update the map with the location
#      of the found interface.


# Exclude devices in "backup mode"
devicesInBackupOpMode = ["atl-edge-fw02"]

# create dicionary by vrf with IP as the key and a list of "locations", which is a tuple of device, interface
'''
{ 'vrf': {
  'name': 'somevrf'
  'ips' : {'1.1.1.1': [('device', 'interface')]}
}
then loop through vrf's and look for ips with len more than 1 to build violations list
'''

vrf_ip_dict = {}
violations = []
for device in dataset['devices']:
  devName = device['name']
  if not (devName in devicesInBackupOpMode):  #devices in backup mode have duplicate IPs intentionally
    for vrf in device['networkInstances']:
      vrf_ip_dict.setdefault(vrf['name'], {'name':vrf['name'],'ips':{} })
      for ints in vrf['interfaces']:
        # iface goes to the root IP interfaces, like tunnel, bridge, SVI
        # subIface goes to the subinterfaces
        if ints['iface']['adminStatus'] =='UP':  #ignore interfaces that are disabled
          intname = ints['iface']['name']
        # logic to grab the right interface 
                # None means its not that int type
                # subinterfaces could be disabled, dont collect that as a conflict
          if ints['subIface'] != None:
            if ints['subIface']['adminStatus'] == 'UP':
              intvalue = ints['subIface']
              intname = ints['subIface']['name']
            else:
              continue  # subint is down so head to next interface
          elif ints['iface']['bridge'] != None:
            intvalue =  ints['iface']['bridge']
          elif ints['iface']['routedVlan'] != None:
            intvalue =  ints['iface']['routedVlan']
          elif ints['iface']['tunnel'] != None:
            intvalue =  ints['iface']['tunnel']
          else:
              continue  # its an interface with no IP, like a switchport
          for ip in intvalue['ipv4']['addresses']:
             # if the IP doesnt have an entry, create one, then add entry
            vrf_ip_dict[vrf['name']]['ips'].setdefault(ip['ip'], [])
            vrf_ip_dict[vrf['name']]['ips'][ip['ip']].insert(0,(device['name'], intname))
            if  len(vrf_ip_dict[vrf['name']]['ips'][ip['ip']]) >1:
              # or should we remove duplicates of the same interface only into violations?
                violations.insert(0,{'ip':ip['ip'], 'vrf': vrf['name'], 'locations': vrf_ip_dict[vrf['name']]['ips'][ip['ip']]})
          # how to add logic for fhrp
          for ip in intvalue['ipv4']['fhrpAddresses']:
            vrf_ip_dict[vrf['name']]['ips'].setdefault(ip['ip'], [])
            vrf_ip_dict[vrf['name']]['ips'][ip['ip']].insert(0,(device['name'], intname))
            if  len(vrf_ip_dict[vrf['name']]['ips'][ip['ip']]) >2:
              # how to remove fhrp from violations? is greater than 2 enough?  Note - not verifiying both in same fhrp peering
                violations.insert(0,{'ip':ip['ip'], 'vrf': vrf['name'], 'locations': vrf_ip_dict[vrf['name']]['ips'][ip['ip']]})

#end of my stuff

if not violations:
    print ("OK")
else:
    print ("Found the following IP uniqueness violations:")
    printTable (
      ["VRF", "Subnet", "Interfaces"],
      [(vio['vrf'], vio['ip'], [d + ":" + i for (d,i) in vio['locations']]) for vio in violations])

