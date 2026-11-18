// Package inventory scans the host and local Docker images with Syft (as a library)
// and produces the InventoryPayload of docs/contracts.md §1.
package inventory

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/cyclonedxjson"

	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"

	"github.com/DonSosiska/holealign/internal/agent/config"
	"github.com/DonSosiska/holealign/internal/model"
)

// Scan scans the host root filesystem and, when the Docker socket exists, every local image.
// A failing image scan is logged and skipped; a failing host scan is an error.
func Scan(ctx context.Context, cfg config.Config) (model.InventoryPayload, error) {
	enc, err := newEncoder()
	if err != nil {
		return model.InventoryPayload{}, err
	}

	hostSBOM, err := safeScan("host", cfg.HostScanTimeout, ctx, func(c context.Context) ([]byte, error) {
		return scanHost(c, cfg, enc)
	})
	if err != nil {
		return model.InventoryPayload{}, fmt.Errorf("scan host: %w", err)
	}
	targets := []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: hostSBOM}}

	if dc := newDockerClient(cfg.DockerSocket); dc != nil {
		refs, err := dc.listImageRefs(ctx)
		if err != nil {
			slog.Warn("docker: listing images failed", "err", err)
		}
		if len(refs) > 0 && os.Getenv("DOCKER_HOST") == "" {
			// stereoscope's docker provider builds its client from the environment
			os.Setenv("DOCKER_HOST", "unix://"+cfg.DockerSocket)
		}
		for _, r := range refs {
			if ctx.Err() != nil {
				return model.InventoryPayload{}, ctx.Err()
			}
			raw, err := safeScan("image "+r.Name, cfg.ImageScanTimeout, ctx, func(c context.Context) ([]byte, error) {
				return scanImage(c, cfg, enc, r)
			})
			if err != nil {
				slog.Warn("scan image failed", "image", r.Name, "err", err)
				continue
			}
			targets = append(targets, model.InventoryTarget{
				Kind: model.TargetContainerImage, Name: r.Name, ImageID: r.ID,
				Containers: r.Containers, SBOM: raw,
			})
		}
	}

	return model.InventoryPayload{
		CollectedAt: time.Now().UTC(),
		Hash:        ComputeHash(targets), // also sorts targets
		Targets:     targets,
	}, nil
}

// safeScan runs fn with a per-scan timeout and converts a panic inside the
// scanner library into an error, so a malformed filesystem cannot crash the agent.
func safeScan(what string, timeout time.Duration, ctx context.Context, fn func(context.Context) ([]byte, error)) (out []byte, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("scan %s panicked: %v", what, r)
		}
	}()
	return fn(ctx)
}

func newEncoder() (sbom.FormatEncoder, error) {
	return cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
}

func sbomConfig(cfg config.Config) *syft.CreateSBOMConfig {
	c := syft.DefaultCreateSBOMConfig().WithoutFiles()
	if !cfg.ScanLanguagePackages {
		// keep the default (source-type) catalogers, narrowed to OS package catalogers
		c = c.WithCatalogerSelection(cataloging.NewSelectionRequest().WithSubSelections(pkgcataloging.OSTag))
	}
	return c
}

// excludePatterns converts absolute paths (/proc) to Syft's root-relative globs (./proc, ./proc/**).
func excludePatterns(paths []string) []string {
	var out []string
	for _, p := range paths {
		if strings.HasPrefix(p, "./") || strings.HasPrefix(p, "*/") || strings.HasPrefix(p, "**/") {
			out = append(out, p)
			continue
		}
		p = strings.Trim(p, "/")
		if p == "" {
			continue
		}
		out = append(out, "./"+p, "./"+p+"/**")
	}
	return out
}

func scanHost(ctx context.Context, cfg config.Config, enc sbom.FormatEncoder) ([]byte, error) {
	gsc := syft.DefaultGetSourceConfig().
		WithSources("dir").
		WithExcludeConfig(source.ExcludeConfig{Paths: excludePatterns(cfg.ExcludePaths)})
	src, err := syft.GetSource(ctx, "/", gsc)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	return catalog(ctx, cfg, enc, src)
}

func scanImage(ctx context.Context, cfg config.Config, enc sbom.FormatEncoder, r imageRef) ([]byte, error) {
	// ID is unambiguous (several tags may share an image); the display name is r.Name.
	gsc := syft.DefaultGetSourceConfig().WithSources("docker")
	src, err := syft.GetSource(ctx, r.ID, gsc)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	return catalog(ctx, cfg, enc, src)
}

func catalog(ctx context.Context, cfg config.Config, enc sbom.FormatEncoder, src source.Source) ([]byte, error) {
	s, err := syft.CreateSBOM(ctx, src, sbomConfig(cfg))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := enc.Encode(&buf, *s); err != nil {
		return nil, fmt.Errorf("encode cyclonedx: %w", err)
	}
	return NormalizeSBOM(buf.Bytes())
}
