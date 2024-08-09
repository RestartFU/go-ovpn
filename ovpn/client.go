package ovpn

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

var (
	nameRegex, _ = regexp.Compile("^[a-zA-Z0-9_-]+$")
)

type Client struct {
	username string
}

func NewClient(name string, psw string) (Client, error) {
	cli := Client{
		username: name,
	}
	if !nameRegex.MatchString(name) {
		return cli, errors.New("invalid client name")
	}

	clients, err := allClientNames()
	if err != nil {
		return cli, err
	}
	if slices.Contains(clients, name) {
		return cli, errors.New("user already exists")
	}

	opt := "inline"
	prefix := fmt.Sprintf("EASYRSA_PASSOUT=pass:%s ", psw)
	if len(psw) <= 0 {
		opt = " nopass"
		prefix = ""
	}

	changeDir := fmt.Sprintf("sudo cd %s", easy_rsa_path)
	buildClient := fmt.Sprintf("sudo %s./easyrsa --batch build-client-full %s %s", prefix, name, opt)
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("%s && %s", changeDir, buildClient))
	cmd.Start()

	generateClientFile(name)
	return cli, nil
}

func allClientNames() ([]string, error) {
	path := "/etc/openvpn/easy-rsa/pki/index.txt"
	content, err := os.ReadFile(path)
	if err != nil {
		return []string{}, err
	}

	lines := strings.Split(string(content), "\n")
	var names []string

	for _, l := range lines {
		sep := strings.Split(l, "/CN=")
		if len(sep) < 2 {
			continue
		}
		names = append(names, sep[1])
	}

	return names, nil
}

func generateClientFile(name string) {
	s := &strings.Builder{}

	writeTemplate(s)
	writeCA(s)
	writeCert(s, name)
	writeKey(s, name)
	writeTLSSig(s)

	os.WriteFile(name+".ovpn", []byte(s.String()), 666)
}

func writeTemplate(s *strings.Builder) error {
	templ, err := readFile(client_template_path)
	if err != nil {
		return err
	}
	s.WriteString(templ)
	s.WriteRune('\n')
	return nil
}

func writeCA(s *strings.Builder) error {
	content, err := readFile(ca_path)
	if err != nil {
		return err
	}
	writeStringWithTag(s, "ca", content)
	return nil
}

func writeCert(s *strings.Builder, name string) error {
	content, err := readFile(cert_path + name + ".crt")
	if err != nil {
		return err
	}
	cert := pullString(string(content), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")
	writeStringWithTag(s, "cert", cert)
	return nil
}

func writeKey(s *strings.Builder, name string) error {
	content, err := readFile(key_path + name + ".key")
	if err != nil {
		return err
	}
	writeStringWithTag(s, "key", content)
	return nil
}

func writeTLSSig(s *strings.Builder) error {
	content, err := readFile(server_conf_path)
	if err != nil {
		return err
	}
	str := string(content)
	if strings.Contains(str, "tls-crypt") {
		crypt, err := readFile(tls_crypt_path)
		if err != nil {
			return err
		}
		writeStringWithTag(s, "tls-crypt", crypt)
	}
	if strings.Contains(str, "tls-auth") {
		auth, err := readFile(tls_auth_path)
		if err != nil {
			return err
		}
		writeStringWithTag(s, "tls-auth", auth)
	}
	return nil
}

func pullString(s, start, end string) string {
	return strings.TrimLeft(strings.TrimRight(s, end), start)
}

func writeStringWithTag(w io.StringWriter, tag string, str string) {
	w.WriteString(fmt.Sprintf("<%s>\n", tag))
	w.WriteString(str)
	w.WriteString(fmt.Sprintf("</%s>\n", tag))
}

func readFile(path string) (string, error) {
	buf, err := os.ReadFile(path)
	return string(buf), err
}
