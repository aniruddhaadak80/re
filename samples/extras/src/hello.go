package main

import (
	"crypto/sha256"
	"fmt"
	"os"
)

type Greeter struct{ Name string }

func (g *Greeter) Greet() string { return "hello " + g.Name }

func revlensChecksum(b []byte) [32]byte { return sha256.Sum256(b) }

func main() {
	g := &Greeter{Name: "revlens"}
	fmt.Println(g.Greet(), revlensChecksum([]byte(os.Args[0]))[0])
}
