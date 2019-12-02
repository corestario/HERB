# Project
domain = "herb.test.dgaming.com"
env_name = "" # should be redefined by CI/CD
testnet_clients_amount = 1 # should be redefined by CI/CD

#testnet_nodes = [
#{
# {region = "fra1"},
# {region = "fra1"}
#}
#] # should be redefined by CI/CD and passed in auto.tfvars file

testnet_prometheus_port = 6060
testnet_client_password = "alicealice"

herb_threshold_1 = 0 # should be redefined by CI/CD
herb_threshold_2 = 0 # should be redefined by CI/CD

#-----
# Provisioner
ansible_workdir = "../ansible"

#-----
# DigitalOcean
## Tested only on Ubuntu
do_image = "ubuntu-18-04-x64"

do_size = "s-1vcpu-1gb"
