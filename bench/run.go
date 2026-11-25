// This package runs the MTC-RT benchmarks from a JSON config and writes one CSV per benchmark.
package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mtcrt/bench/benchmarks"
	"mtcrt/bench/config"
)

// Runs every selected benchmark and writes its CSV.
func Run(cfg config.Config, configPath string, configJSON []byte, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}

	if err := os.MkdirAll(cfg.Out, 0o755); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(cfg.Out, "config.json"), configJSON, 0o644); err != nil {
		return err
	}

	if err := writeMeta(cfg.Out, configPath); err != nil {
		return err
	}

	for _, name := range cfg.Benchmarks {
		cases, err := cfg.Expand(name)
		if err != nil {
			return err
		}

		switch name {
		case "storage":
			err = benchmarks.RunStorage(cfg, cases, progress)
		case "rp-sync":
			err = benchmarks.RunRPSync(cfg, cases, progress)
		case "disclosure":
			err = benchmarks.RunDisclosure(cfg, cases, progress)
		case "epoch":
			err = benchmarks.RunEpoch(cfg, cases, progress)
		case "lookup":
			err = benchmarks.RunLookup(cfg, cases, progress)
		default:
			err = fmt.Errorf("unknown benchmark %q", name)
		}

		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	return nil
}

// Metadata about machine and config.
type metadata struct {
	GoVersion  string    `json:"go_version"`
	GOOS       string    `json:"goos"`
	GOARCH     string    `json:"goarch"`
	CPUModel   string    `json:"cpu_model"`
	Cores      int       `json:"cores"`
	ConfigPath string    `json:"config_path"`
	StartTime  time.Time `json:"start_time"`
}

// Writes meta.json
func writeMeta(out, configPath string) error {
	m := metadata{
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		CPUModel: cpuModel(), Cores: runtime.NumCPU(),
		ConfigPath: configPath, StartTime: time.Now().UTC(),
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(out, "meta.json"), data, 0o644)
}

// Returns a short name for this machine's CPU.
func cpuModel() string {
	switch runtime.GOOS {
	case "windows":
		if out := commandOutput("powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)"); out != "" {
			return out
		}
	case "linux":
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if key, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) == "model name" {
					return strings.TrimSpace(value)
				}
			}
		}
	}

	return "unknown"
}

// Runs a command and returns its output.
func commandOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}
