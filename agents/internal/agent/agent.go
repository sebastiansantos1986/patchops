package agent

import (
	"context"
	"fmt"
)

// Agent owns the platform-neutral lifecycle. OS-specific inventory and patch
// execution will be injected behind narrow interfaces as the POC evolves.
type Agent struct { platform string }

func New(platform string) *Agent { return &Agent{platform: platform} }

func (a *Agent) Run(ctx context.Context, once bool) error {
	if a.platform != "darwin" && a.platform != "windows" && a.platform != "linux" {
		return fmt.Errorf("unsupported platform %q", a.platform)
	}
	// Foundation milestone: config -> identity -> inventory -> desired state -> result.
	// No privileged package execution is implemented until trust validation exists.
	return nil
}
