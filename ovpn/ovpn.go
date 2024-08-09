package ovpn

var (
	open_vpn_path = "/etc/openvpn/"
	easy_rsa_path = open_vpn_path + "easy-rsa/"

	server_conf_path     = open_vpn_path + "server.conf"
	tls_crypt_path       = open_vpn_path + "tls-crypt.key"
	tls_auth_path        = open_vpn_path + "tls-auth.key"
	client_template_path = open_vpn_path + "client-template.txt"
	ca_path              = easy_rsa_path + "pki/ca.crt"
	cert_path            = easy_rsa_path + "pki/issued/"
	key_path             = easy_rsa_path + "pki/key/"
)
