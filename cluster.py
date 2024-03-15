from kubernetes import client, config
from pprint import pprint
from argparse import Namespace
import os, sys
import string

def get_cluster_name(args: Namespace):
  if args.name is not None:
    if not all(c in (string.ascii_letters + string.digits + '_' + '-') for c in args.name):
        sys.exit("-n/--name must contain only letters, numbers, '-' or '_'!")
    return args.name

  if "KUBECONFIG" in os.environ:
    config.load_kube_config()
  else:
    config.incluster_config.load_incluster_config()

  crd = client.CustomObjectsApi()

  infrastructure = crd.get_cluster_custom_object(
     "config.openshift.io",
     "v1",
     "infrastructures",
     "cluster"
  )

  return infrastructure.get("status").get("infrastructureName").split("-")[0]
