# Managed by Terraform, don't change by hand
all:
  vars:
    domain: '${domain}'
    env_name: '${env_name}'
    testnet_prometheus_port: '${testnet_prometheus_port}'
    testnet_clients_amount: ${testnet_clients_amount}
    testnet_client_password: '${testnet_client_password}'
    dwh_prometheus_port: '${dwh_prometheus_port}'

    herb_threshold_1: ${herb_threshold_1}
    herb_threshold_2: ${herb_threshold_2}

  children:
    testnet:
      hosts:
%{for node in testnet_nodes}
        ${replace(node.name, join("", [".", domain]), "")}:
          ansible_host: ${node.ipv4_address}
          private_addr: ${node.ipv4_address_private}
%{endfor}

    dwh:
      hosts:
        ${replace(dwh_node.name, join("", [".", domain]), "")}:
          ansible_host: ${dwh_node.ipv4_address}
          private_addr: ${dwh_node.ipv4_address_private}
