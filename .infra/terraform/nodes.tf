# Bootstrap VMs
resource "digitalocean_droplet" "testnet" {
  count = "${length(var.testnet_nodes)}"

  name = "node${count.index}-${var.testnet_nodes[count.index].region}.${var.env_name}.${var.domain}"
  image = var.do_image
  size = var.do_size
  private_networking = true
  region = "${var.testnet_nodes[count.index].region}"
  ssh_keys = digitalocean_ssh_key.provisioner_ssh_key[*].fingerprint
}
