package ovpn

var (
	openVpnPath = "/etc/openvpn/"
	easyRsaPath = openVpnPath + "easy-rsa/"

	serverConfPath     = openVpnPath + "server.conf"
	tlsCryptPath       = openVpnPath + "tls-crypt.key"
	tlsAuthPath        = openVpnPath + "tls-auth.key"
	clientTemplatePath = openVpnPath + "client-template.txt"
	indexPath          = easyRsaPath + "pki/index.txt"
	caPath             = easyRsaPath + "pki/ca.crt"
	certPath           = easyRsaPath + "pki/issued/"
	keyPath            = easyRsaPath + "pki/key/"
)
