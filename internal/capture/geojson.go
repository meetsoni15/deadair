// Package capture — GeoJSON wardriving export.
// Tags each discovered AP with GPS coordinates and exports to warmap.geojson.
package capture

import (
	"encoding/json"
	"net"
	"os"
	"sync"
)

// GeoEntry is one geotagged AP observation.
type GeoEntry struct {
	BSSID net.HardwareAddr
	SSID  string
	RSSI  int8
	Lat   float64
	Lon   float64
}

// GeoWriter accumulates geotagged observations and exports GeoJSON.
type GeoWriter struct {
	mu      sync.Mutex
	entries []GeoEntry
	OutFile string
}

// NewGeoWriter creates a GeoWriter that writes to outFile on Save().
func NewGeoWriter(outFile string) *GeoWriter {
	return &GeoWriter{OutFile: outFile}
}

// Record adds a geotagged AP sighting.
func (g *GeoWriter) Record(bssid net.HardwareAddr, ssid string, rssi int8, lat, lon float64) {
	if lat == 0 && lon == 0 {
		return // no fix yet
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.entries = append(g.entries, GeoEntry{
		BSSID: bssid,
		SSID:  ssid,
		RSSI:  rssi,
		Lat:   lat,
		Lon:   lon,
	})
}

// Save writes all entries to the GeoJSON file.
func (g *GeoWriter) Save() error {
	if g.OutFile == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	type properties struct {
		BSSID string `json:"bssid"`
		SSID  string `json:"ssid"`
		RSSI  int8   `json:"rssi_dbm"`
	}
	type geometry struct {
		Type        string    `json:"type"`
		Coordinates []float64 `json:"coordinates"`
	}
	type feature struct {
		Type       string     `json:"type"`
		Geometry   geometry   `json:"geometry"`
		Properties properties `json:"properties"`
	}
	type featureCollection struct {
		Type     string    `json:"type"`
		Features []feature `json:"features"`
	}

	features := make([]feature, len(g.entries))
	for i, e := range g.entries {
		features[i] = feature{
			Type: "Feature",
			Geometry: geometry{
				Type:        "Point",
				Coordinates: []float64{e.Lon, e.Lat}, // GeoJSON is [lon, lat]
			},
			Properties: properties{
				BSSID: e.BSSID.String(),
				SSID:  e.SSID,
				RSSI:  e.RSSI,
			},
		}
	}

	fc := featureCollection{Type: "FeatureCollection", Features: features}
	data, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(g.OutFile, data, 0644)
}
