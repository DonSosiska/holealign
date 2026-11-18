package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// dockerClient is a minimal Docker Engine API client over a unix socket (plain net/http).
type dockerClient struct {
	http *http.Client
}

type dockerImage struct {
	ID       string   `json:"Id"`
	RepoTags []string `json:"RepoTags"`
}

type dockerContainer struct {
	Names   []string `json:"Names"`
	ImageID string   `json:"ImageID"`
}

// newDockerClient returns nil when the socket does not exist.
func newDockerClient(socket string) *dockerClient {
	if socket == "" {
		return nil
	}
	if st, err := os.Stat(socket); err != nil || st.Mode()&os.ModeSocket == 0 {
		return nil
	}
	// One transport per client, so idle connections must not be kept: otherwise every
	// check-in leaks a connection and its goroutines until the collector runs out of fds.
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &dockerClient{http: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

func (d *dockerClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker GET %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (d *dockerClient) images(ctx context.Context) ([]dockerImage, error) {
	var imgs []dockerImage
	err := d.get(ctx, "/images/json", &imgs)
	return imgs, err
}

func (d *dockerClient) containers(ctx context.Context) ([]dockerContainer, error) {
	var cs []dockerContainer
	err := d.get(ctx, "/containers/json", &cs)
	return cs, err
}

// imageRef is one scannable image (deduplicated by image ID).
type imageRef struct {
	ID         string
	Name       string   // first sorted repo tag, or the image ID when untagged
	Containers []string // running container names
}

// buildImageRefs merges the image and container listings into one entry per image ID, sorted by name.
func buildImageRefs(imgs []dockerImage, cs []dockerContainer) []imageRef {
	byID := map[string]*imageRef{}
	for _, im := range imgs {
		var tags []string
		for _, t := range im.RepoTags {
			if t != "" && !strings.HasPrefix(t, "<none>") {
				tags = append(tags, t)
			}
		}
		sort.Strings(tags)
		name := im.ID
		if len(tags) > 0 {
			name = tags[0]
		}
		byID[im.ID] = &imageRef{ID: im.ID, Name: name}
	}
	for _, c := range cs {
		r, ok := byID[c.ImageID]
		if !ok {
			continue
		}
		for _, n := range c.Names {
			r.Containers = append(r.Containers, strings.TrimPrefix(n, "/"))
		}
	}
	out := make([]imageRef, 0, len(byID))
	for _, r := range byID {
		sort.Strings(r.Containers)
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// listImageRefs lists images and running containers.
func (d *dockerClient) listImageRefs(ctx context.Context) ([]imageRef, error) {
	imgs, err := d.images(ctx)
	if err != nil {
		return nil, err
	}
	cs, err := d.containers(ctx)
	if err != nil {
		cs = nil // container names are best effort
	}
	return buildImageRefs(imgs, cs), nil
}
