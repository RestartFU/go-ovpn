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

func NewClient(name string, psw string) error {
	if !nameRegex.MatchString(name) {
		return errors.New("invalid client name")
	}
	clients, err := allClientNames()
	if err != nil {
		return err
	}
	if slices.Contains(clients, name) {
		return errors.New("user already exists")
	}
	opt := ""
	prefix := fmt.Sprintf("EASYRSA_PASSOUT=pass:%s ", psw)
	if len(psw) <= 0 {
		opt = " nopass"
		prefix = ""
	}

	cmd := exec.Command("/bin/bash", "-c", "sudo cd /etc/openvpn/easy-rsa && sudo "+prefix+"./easyrsa --batch build-client-full "+name+opt)
	cmd.Start()

	generateClientFile(name)
	return nil
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

func writeTemplate(s *strings.Builder) {
	templ, err := os.ReadFile("/etc/openvpn/client-template.txt")
	if err != nil {
		panic(err)
	}
	s.Write(templ)
	s.WriteRune('\n')
}

func writeCA(s *strings.Builder) error {
	content, err := os.ReadFile("/etc/openvpn/easy-rsa/pki/ca.crt")
	if err != nil {
		return err
	}
	writeStringWithTag(s, "ca", string(content))
	return nil
}

func writeCert(s *strings.Builder, name string) error {
	content, err := os.ReadFile("/etc/openvpn/easy-rsa/pki/issued/" + name + ".crt")
	if err != nil {
		return err
	}
	cert := pullString(string(content), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")
	writeStringWithTag(s, "cert", cert)
	return nil
}

func writeKey(s *strings.Builder, name string) error {
	content, err := os.ReadFile("/etc/openvpn/easy-rsa/pki/private/" + name + ".key")
	if err != nil {
		return err
	}
	writeStringWithTag(s, "key", string(content))
	return nil
}

func writeTLSSig(s *strings.Builder) {
	content, err := os.ReadFile("/etc/openvpn/server.conf")
	if err != nil {
		panic(err)
	}
	str := string(content)
	if strings.Contains(str, "tls-crypt") {
		crypt, err := os.ReadFile("/etc/openvpn/tls-crypt.key")
		if err != nil {
			panic(err)
		}
		writeStringWithTag(s, "tls-crypt", string(crypt))
	}
	if strings.Contains(str, "tls-auth") {
		auth, err := os.ReadFile("/etc/openvpn/tls-crypt.key")
		if err != nil {
			panic(err)
		}
		writeStringWithTag(s, "tls-auth", string(auth))
	}
}

func pullString(s, start, end string) string {
	return strings.TrimLeft(strings.TrimRight(s, end), start)
}

func writeStringWithTag(w io.StringWriter, tag string, str string) {
	w.WriteString(fmt.Sprintf("<%s>\n", tag))
	w.WriteString(str)
	w.WriteString(fmt.Sprintf("</%s>\n", tag))
}
