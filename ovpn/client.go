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

func ClientByName(name string) (Client, bool) {
	clients, err := Clients()
	if err != nil {
		return Client{}, false
	}
	for _, c := range clients {
		if strings.EqualFold(c.username, name) {
			return c, true
		}
	}
	return Client{}, false
}

func Clients() ([]Client, error) {
	content, err := readFile(indexPath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(content, "\n")
	var clients []Client

	for _, l := range lines {
		sep := strings.Split(l, "/CN=")
		if len(sep) < 2 || l[0] == 'R' {
			continue
		}
		clients = append(clients, Client{username: sep[1]})
	}
	return clients, nil
}

type Client struct {
	username string
}

func NewClient(name string, psw string) (Client, error) {
	cli := Client{username: name}
	if !nameRegex.MatchString(name) {
		return cli, errors.New("invalid client name")
	}

	clients, err := Clients()
	if err != nil {
		return cli, err
	}
	if slices.ContainsFunc(clients, func(c Client) bool { return strings.EqualFold(c.username, name) }) {
		return cli, errors.New("user already exists")
	}

	opt := "inline"
	prefix := fmt.Sprintf("EASYRSA_PASSOUT=pass:%s ", psw)
	if len(psw) <= 0 {
		opt = "nopass"
		prefix = ""
	}

	changeDir := fmt.Sprintf("cd %s", easyRsaPath)
	buildClient := fmt.Sprintf("sudo %s./easyrsa --batch build-client-full %s %s", prefix, name, opt)
	fmt.Println(fmt.Sprintf("%s && %s", changeDir, buildClient))
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("%s && %s", changeDir, buildClient))
	cmd.Start()

	os.WriteFile(name+".ovpn", []byte(cli.Config()), 666)
	return cli, nil
}

func RevokeClient(cli Client) error {
	var newIndex []string

	content, err := readFile(indexPath)
	if err != nil {
		return err
	}
	lines := strings.Split(content, "\n")

	for _, l := range lines {
		sep := strings.Split(l, "/CN=")
		if len(sep) >= 2 && strings.EqualFold(sep[1], cli.username) {
			continue
		}
		newIndex = append(newIndex, l)
	}
	os.WriteFile(indexPath, []byte(strings.Join(newIndex, "\n")), 666)

	changeDir := fmt.Sprintf("cd %s", easyRsaPath)
	revokeClient := fmt.Sprintf("sudo ./easyrsa --batch revoke %s", cli.username)
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("%s && %s", changeDir, revokeClient))
	cmd.Start()

	return nil
}

func (c Client) Config() string {
	s := &strings.Builder{}

	writeTemplate(s)
	writeCA(s)
	writeCert(s, c.username)
	writeKey(s, c.username)
	writeTLSSig(s)

	return s.String()
}

func (c Client) Username() string {
	return c.username
}

func writeTemplate(s *strings.Builder) error {
	templ, err := readFile(clientTemplatePath)
	if err != nil {
		return err
	}
	s.WriteString(templ)
	s.WriteRune('\n')
	return nil
}

func writeCA(s *strings.Builder) error {
	content, err := readFile(caPath)
	if err != nil {
		return err
	}
	writeStringWithTag(s, "ca", content)
	return nil
}

func writeCert(s *strings.Builder, name string) error {
	content, err := readFile(certPath + name + ".crt")
	if err != nil {
		return err
	}
	cert := pullString(string(content), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")
	writeStringWithTag(s, "cert", cert)
	return nil
}

func writeKey(s *strings.Builder, name string) error {
	content, err := readFile(keyPath + name + ".key")
	if err != nil {
		return err
	}
	writeStringWithTag(s, "key", content)
	return nil
}

func writeTLSSig(s *strings.Builder) error {
	content, err := readFile(serverConfPath)
	if err != nil {
		return err
	}
	str := string(content)
	if strings.Contains(str, "tls-crypt") {
		crypt, err := readFile(tlsCryptPath)
		if err != nil {
			return err
		}
		writeStringWithTag(s, "tls-crypt", crypt)
	}
	if strings.Contains(str, "tls-auth") {
		auth, err := readFile(tlsAuthPath)
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
