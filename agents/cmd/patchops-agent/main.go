package main

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"time"

	"github.com/sebastiansantos1986/patchops/agents/internal/agent"
)

func main() {
	once := flag.Bool("once", false, "run one inventory/check-in cycle")
	flag.Parse()
	runner := agent.New(runtime.GOOS)
	if err := runner.Run(context.Background(), *once); err != nil { panic(err) }
	fmt.Printf("PatchOps agent cycle complete at %s\n", time.Now().Format(time.RFC3339))
}
