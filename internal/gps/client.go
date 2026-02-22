// Package gps connects to gpsd and provides real-time coordinates.
// Enable with --gps. Requires gpsd running on localhost:2947.
package gps

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

// Fix holds the latest GPS position.
type Fix struct {
	Lat   float64
	Lon   float64
	Alt   float64
	Valid bool
}

// Client streams position fixes from gpsd.
type Client struct {
	mu      sync.RWMutex
	current Fix
	done    chan struct{}
}

// NewClient creates a GPS client (not yet connected).
func NewClient() *Client {
	return &Client{done: make(chan struct{})}
}

// Run connects to gpsd and streams TPV (time-position-velocity) records.
// Call in a goroutine. Non-fatal if gpsd is unavailable.
func (c *Client) Run(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("gpsd connect: %w", err)
	}
	defer conn.Close()

	// Enable JSON streaming
	fmt.Fprintln(conn, `?WATCH={"enable":true,"json":true}`)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case <-c.done:
			return nil
		default:
		}

		var msg map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}
		if msg["class"] != "TPV" {
			continue
		}

		lat, _ := msg["lat"].(float64)
		lon, _ := msg["lon"].(float64)
		alt, _ := msg["alt"].(float64)
		mode, _ := msg["mode"].(float64)

		c.mu.Lock()
		c.current = Fix{
			Lat:   lat,
			Lon:   lon,
			Alt:   alt,
			Valid: mode >= 2, // 2=2D fix, 3=3D fix
		}
		c.mu.Unlock()
	}
	return nil
}

// Current returns the latest GPS fix.
func (c *Client) Current() Fix {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// Stop signals the client to disconnect.
func (c *Client) Stop() {
	close(c.done)
}
