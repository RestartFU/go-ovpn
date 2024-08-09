package main

import (
	"math/rand"
	"strconv"

	"github.com/cadre-vpn/go-ovpn/ovpn"
)

func main() {
	_, err := ovpn.NewClient("client"+strconv.Itoa(int(rand.Uint32())), "")
	if err != nil {
		panic(err)
	}

	//fmt.Println(cli.Config())
	//ovpn.RevokeClient(cli)
}
