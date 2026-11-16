package facts

import (
	"context"
	"strings"

	"panoptes/internal/model"
)

// parseSystemctl extracts unit names (without ".service") from
// `systemctl list-units --type=service --state=running --no-legend`.
func parseSystemctl(out []byte) []string {
	names := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if name == "●" && len(fields) > 1 {
			name = fields[1]
		}
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		names = append(names, strings.TrimSuffix(name, ".service"))
	}
	return names
}

func collectServices(ctx context.Context, env *Env) model.Facts {
	out, err := env.run(ctx, "systemctl", "list-units", "--type=service", "--state=running", "--no-legend")
	if err != nil {
		return model.Facts{}
	}
	return model.Facts{"services.active": parseSystemctl(out)}
}
