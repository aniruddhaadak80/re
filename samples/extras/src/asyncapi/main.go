// Small Go program that embeds two AsyncAPI documents, the way services ship their contracts.
package main

import (
	_ "embed"
	"fmt"
	"os"
)

//go:embed streetlights-mqtt-2.6.yml
var specV2 string

//go:embed streetlights-mqtt-3.0.yml
var specV3 string

func main() {
	if len(os.Args) > 1 && os.Args[1] == "v2" {
		fmt.Print(specV2)
		return
	}
	fmt.Print(specV3)
}
