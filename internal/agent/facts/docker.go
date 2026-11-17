package facts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

const (
	dockerMaxBody       = 4 << 20
	dockerMaxContainers = 500
)

type dockerVersionResp struct {
	Version string `json:"Version"`
}

type dockerPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type dockerContainerResp struct {
	ID      string       `json:"Id"`
	Names   []string     `json:"Names"`
	Image   string       `json:"Image"`
	ImageID string       `json:"ImageID"`
	Ports   []dockerPort `json:"Ports"`
}

type dockerInspectResp struct {
	HostConfig struct {
		Privileged bool `json:"Privileged"`
	} `json:"HostConfig"`
}

// newDockerClient returns an HTTP client that always dials the given unix socket.
func newDockerClient(socket string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
	}
}

// dockerGet performs GET path against the Engine API and decodes the JSON body into v.
func dockerGet(ctx context.Context, client *http.Client, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, dockerMaxBody))
		return fmt.Errorf("docker API %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, dockerMaxBody)).Decode(v)
}

// formatDockerPorts renders port mappings as "ip:public->private/proto" or "private/proto".
func formatDockerPorts(ports []dockerPort) []string {
	out := []string{}
	for _, p := range ports {
		if p.PublicPort > 0 {
			ip := p.IP
			if ip == "" {
				ip = "0.0.0.0"
			}
			out = append(out, fmt.Sprintf("%s:%d->%d/%s", ip, p.PublicPort, p.PrivatePort, p.Type))
		} else {
			out = append(out, fmt.Sprintf("%d/%s", p.PrivatePort, p.Type))
		}
	}
	return out
}

func collectDocker(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}
	if env.DockerSocket == "" {
		f["docker.installed"] = false
		return f
	}
	if _, err := os.Stat(env.DockerSocket); os.IsNotExist(err) {
		f["docker.installed"] = false
		return f
	}

	client := newDockerClient(env.DockerSocket)

	var ver dockerVersionResp
	if err := dockerGet(ctx, client, "/version", &ver); err != nil {
		return model.Facts{} // socket present but API unusable: unknown
	}
	f["docker.installed"] = true
	f["docker.version"] = ver.Version

	var list []dockerContainerResp
	if err := dockerGet(ctx, client, "/containers/json", &list); err != nil {
		return f
	}
	if len(list) > dockerMaxContainers {
		list = list[:dockerMaxContainers]
	}

	containers := make([]map[string]any, 0, len(list))
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		entry := map[string]any{
			"name":     name,
			"image":    c.Image,
			"image_id": c.ImageID,
			"ports":    formatDockerPorts(c.Ports),
		}
		var insp dockerInspectResp
		if err := dockerGet(ctx, client, "/containers/"+c.ID+"/json", &insp); err == nil {
			entry["privileged"] = insp.HostConfig.Privileged
		}
		containers = append(containers, entry)
	}
	f["docker.containers"] = containers
	return f
}
