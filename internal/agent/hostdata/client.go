package hostdata

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"panoptes/internal/model"
)

// Protocol limits (docs/contracts.md §2). One request per connection.
const (
	MaxRequestBytes  = 64 << 10  // request line cap enforced by the collector
	MaxResponseBytes = 256 << 20 // decompressed response cap enforced by the client
)

// Operations.
const (
	OpFacts     = "facts"
	OpInventory = "inventory"
	OpOSInfo    = "osinfo"
	OpChanged   = "changed"
)

// Request is one newline-terminated JSON line.
type Request struct {
	Op           string              `json:"op"`
	FactRequests []model.FactRequest `json:"fact_requests,omitempty"`
	Gzip         bool                `json:"gzip,omitempty"` // gzip the response (used for inventory)
}

// Response is the (possibly gzip-compressed) JSON answer.
type Response struct {
	OK        bool                    `json:"ok"`
	Error     string                  `json:"error,omitempty"`
	Facts     model.Facts             `json:"facts,omitempty"`
	Inventory *model.InventoryPayload `json:"inventory,omitempty"`
	OS        *model.OSInfo           `json:"os,omitempty"`
	MachineID string                  `json:"machine_id,omitempty"`
	Changed   bool                    `json:"changed"`
}

// Client is a Source that asks the collector over its unix socket.
type Client struct {
	Path string
	// per-operation time limits
	QuickTimeout     time.Duration // facts, osinfo, changed
	InventoryTimeout time.Duration
}

// NewClient returns a socket Source.
func NewClient(path string) *Client {
	return &Client{Path: path, QuickTimeout: 3 * time.Minute, InventoryTimeout: time.Hour}
}

func (c *Client) call(ctx context.Context, req Request, timeout time.Duration) (Response, error) {
	var resp Response
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return resp, fmt.Errorf("collector unavailable: %w", err)
	}
	defer conn.Close()
	// abort blocked I/O when the context ends
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	line, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	if len(line)+1 > MaxRequestBytes {
		return resp, errors.New("collector request too large")
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return resp, fmt.Errorf("collector write: %w", err)
	}
	br := bufio.NewReader(conn)
	var r io.Reader = br
	// gzip magic: the collector compresses when asked, but answers errors in plain JSON
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return resp, fmt.Errorf("collector response: %w", ctxErr(ctx, err))
		}
		defer zr.Close()
		r = zr
	}
	if err := json.NewDecoder(io.LimitReader(r, MaxResponseBytes)).Decode(&resp); err != nil {
		return resp, fmt.Errorf("collector response: %w", ctxErr(ctx, err))
	}
	if !resp.OK {
		return resp, fmt.Errorf("collector: %s", resp.Error)
	}
	return resp, nil
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (c *Client) Facts(ctx context.Context, reqs []model.FactRequest) (model.Facts, error) {
	resp, err := c.call(ctx, Request{Op: OpFacts, FactRequests: reqs}, c.QuickTimeout)
	if err != nil {
		return nil, err
	}
	if resp.Facts == nil {
		resp.Facts = model.Facts{}
	}
	return resp.Facts, nil
}

func (c *Client) Inventory(ctx context.Context) (model.InventoryPayload, error) {
	resp, err := c.call(ctx, Request{Op: OpInventory, Gzip: true}, c.InventoryTimeout)
	if err != nil {
		return model.InventoryPayload{}, err
	}
	if resp.Inventory == nil {
		return model.InventoryPayload{}, errors.New("collector: empty inventory response")
	}
	return *resp.Inventory, nil
}

func (c *Client) Info(ctx context.Context) (HostInfo, error) {
	resp, err := c.call(ctx, Request{Op: OpOSInfo}, c.QuickTimeout)
	if err != nil {
		return HostInfo{}, err
	}
	if resp.OS == nil {
		return HostInfo{}, errors.New("collector: empty osinfo response")
	}
	return HostInfo{OS: *resp.OS, MachineID: resp.MachineID}, nil
}

func (c *Client) Changed(ctx context.Context) (bool, error) {
	resp, err := c.call(ctx, Request{Op: OpChanged}, c.QuickTimeout)
	if err != nil {
		return false, err
	}
	return resp.Changed, nil
}
