package main

import (
	"bufio"
	"context"
	"os"

	"github.com/GoogleCloudPlatform/artifact-registry-apt-transport/apt"
)

func main() {
	apt := apt.NewAptMethod(os.Stdout, bufio.NewReader(os.Stdin))
	apt.Run(context.Background())
}
