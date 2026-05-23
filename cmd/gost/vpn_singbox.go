package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const vpnStateFile = "vpn-state.json"

type vpnRuntimeState struct {
	PID          int       `json:"pid"`
	Executable   string    `json:"executable"`
	Profile      string    `json:"profile"`
	ConfigPath   string    `json:"configPath"`
	ConfigSHA256 string    `json:"configSha256"`
	LogPath      string    `json:"logPath"`
	StartedAt    time.Time `json:"startedAt"`
}

type singBoxConfig struct {
	Log       singBoxLog        `json:"log,omitempty"`
	DNS       singBoxDNS        `json:"dns,omitempty"`
	Inbounds  []singBoxInbound  `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Route     singBoxRoute      `json:"route"`
}

type singBoxLog struct {
	Level string `json:"level,omitempty"`
}

type singBoxInbound struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	InterfaceName string   `json:"interface_name,omitempty"`
	Address       []string `json:"address"`
	MTU           uint32   `json:"mtu,omitempty"`
	AutoRoute     bool     `json:"auto_route"`
	StrictRoute   bool     `json:"strict_route"`
	Stack         string   `json:"stack,omitempty"`
}

type singBoxDNS struct {
	Servers  []json.RawMessage `json:"servers"`
	Final    string            `json:"final,omitempty"`
	Strategy string            `json:"strategy,omitempty"`
}

type singBoxDNSServerUDP struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

type singBoxDNSServerHTTPS struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
	Path       string `json:"path,omitempty"`
	Detour     string `json:"detour,omitempty"`
}

type singBoxRoute struct {
	AutoDetectInterface   bool               `json:"auto_detect_interface"`
	Rules                 []singBoxRouteRule `json:"rules,omitempty"`
	Final                 string             `json:"final"`
	DefaultDomainResolver string             `json:"default_domain_resolver,omitempty"`
}

type singBoxRouteRule struct {
	Protocol string `json:"protocol,omitempty"`
	Network  string `json:"network,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Action   string `json:"action,omitempty"`
}

type singBoxSocksOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
	Version    string `json:"version"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
}

type singBoxHTTPOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
}

func startVPNModeForSelectedProfile(reader *bufio.Reader, store *profileStore) error {
	idx, err := selectedProfileIndex(reader, store)
	if err != nil {
		return err
	}
	profile := &store.Profiles[idx]

	if !currentProcessCanStartVPN() {
		return errors.New("VPN mode requires an Administrator terminal")
	}
	if running, state := vpnModeRunning(); running {
		return fmt.Errorf("VPN mode is already running for %q (pid %d). Choose 12 to stop it first", state.Profile, state.PID)
	}

	singBoxPath, err := findSingBox()
	if err != nil {
		return err
	}

	cfg, err := buildSingBoxConfig(profile)
	if err != nil {
		return err
	}

	dir, err := vpnRuntimeDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	slug := profileSlug(profile.Name)
	configPath := filepath.Join(dir, slug+".json")
	logPath := filepath.Join(dir, slug+".log")
	configData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	configData = append(configData, '\n')
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		return err
	}
	if err := checkSingBoxConfig(singBoxPath, configPath); err != nil {
		return err
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	_ = disableSystemProxy()

	cmd := exec.Command(singBoxPath, "run", "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return err
	}

	state := vpnRuntimeState{
		PID:          cmd.Process.Pid,
		Executable:   singBoxPath,
		Profile:      profile.Name,
		ConfigPath:   configPath,
		ConfigSHA256: sha256Hex(configData),
		LogPath:      logPath,
		StartedAt:    time.Now(),
	}
	if err := saveVPNState(state); err != nil {
		_ = cmd.Process.Kill()
		logFile.Close()
		return err
	}

	go func() {
		err := cmd.Wait()
		logFile.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "VPN backend exited: %v\n", err)
		}
		clearVPNStateIfPID(state.PID)
	}()

	fmt.Fprintf(os.Stdout, "VPN mode started for %s (pid %d).\n", profile.Name, state.PID)
	fmt.Fprintf(os.Stdout, "Backend: %s\n", singBoxPath)
	fmt.Fprintf(os.Stdout, "Config: %s\n", configPath)
	fmt.Fprintln(os.Stdout, "Choose 12 to stop VPN mode.")
	return nil
}

func printVPNStatus() error {
	running, state := vpnModeRunning()
	if !running {
		fmt.Fprintln(os.Stdout, "VPN mode: stopped")
		return nil
	}

	fmt.Fprintln(os.Stdout, "VPN mode: running")
	fmt.Fprintf(os.Stdout, "Profile: %s\n", state.Profile)
	fmt.Fprintf(os.Stdout, "PID: %d\n", state.PID)
	fmt.Fprintf(os.Stdout, "Backend: %s\n", state.Executable)
	fmt.Fprintf(os.Stdout, "Config: %s\n", state.ConfigPath)
	fmt.Fprintf(os.Stdout, "Started: %s\n", state.StartedAt.Format(time.RFC3339))
	return nil
}

func checkVPNBackend() error {
	singBoxPath, err := findSingBox()
	if err != nil {
		return err
	}
	version, err := exec.Command(singBoxPath, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box version check failed: %w: %s", err, strings.TrimSpace(string(version)))
	}
	fmt.Fprintf(os.Stdout, "Backend: %s\n", singBoxPath)
	fmt.Fprintln(os.Stdout, strings.TrimSpace(string(version)))
	if currentProcessCanStartVPN() {
		fmt.Fprintln(os.Stdout, "Administrator: yes")
	} else {
		fmt.Fprintln(os.Stdout, "Administrator: no; VPN mode needs an Administrator terminal")
	}
	return nil
}

func stopVPNMode() error {
	state, err := loadVPNState()
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("VPN mode is not running")
		}
		return err
	}

	if !processMatches(state.PID, state.Executable) {
		_ = clearVPNState()
		return errors.New("VPN state was stale; no matching sing-box process is running")
	}

	process, err := os.FindProcess(state.PID)
	if err != nil {
		return err
	}
	if err := process.Kill(); err != nil && processExists(state.PID) {
		return err
	}
	return clearVPNState()
}

func buildSingBoxConfig(profile *proxyProfile) (singBoxConfig, error) {
	outbound, err := singBoxOutboundForProfile(profile)
	if err != nil {
		return singBoxConfig{}, err
	}
	dns, err := singBoxDNSConfig()
	if err != nil {
		return singBoxConfig{}, err
	}

	return singBoxConfig{
		Log: singBoxLog{Level: "info"},
		DNS: dns,
		Inbounds: []singBoxInbound{
			{
				Type:          "tun",
				Tag:           "tun-in",
				InterfaceName: "gost-tun",
				Address:       []string{"172.19.0.1/30"},
				MTU:           9000,
				AutoRoute:     true,
				StrictRoute:   true,
				Stack:         "gvisor",
			},
		},
		Outbounds: []json.RawMessage{outbound},
		Route: singBoxRoute{
			AutoDetectInterface: true,
			Rules: []singBoxRouteRule{
				{Protocol: "dns", Action: "hijack-dns"},
				{Network: "udp", Port: 53, Action: "hijack-dns"},
				{Network: "tcp", Port: 53, Action: "hijack-dns"},
			},
			Final:                 "proxy",
			DefaultDomainResolver: "bootstrap",
		},
	}, nil
}

func singBoxDNSConfig() (singBoxDNS, error) {
	bootstrap, err := json.Marshal(singBoxDNSServerUDP{
		Type:       "udp",
		Tag:        "bootstrap",
		Server:     "1.1.1.1",
		ServerPort: 53,
	})
	if err != nil {
		return singBoxDNS{}, err
	}
	remote, err := json.Marshal(singBoxDNSServerHTTPS{
		Type:       "https",
		Tag:        "remote",
		Server:     "1.1.1.1",
		ServerPort: 443,
		Path:       "/dns-query",
		Detour:     "proxy",
	})
	if err != nil {
		return singBoxDNS{}, err
	}

	return singBoxDNS{
		Servers:  []json.RawMessage{bootstrap, remote},
		Final:    "remote",
		Strategy: "prefer_ipv4",
	}, nil
}

func singBoxOutboundForProfile(profile *proxyProfile) (json.RawMessage, error) {
	route := checkRoute(profile)
	if len(route.ChainNodes) == 0 {
		return nil, errors.New("VPN mode needs an Upstream proxy in the selected profile")
	}
	if len(route.ChainNodes) > 1 {
		return nil, errors.New("VPN mode currently supports one Upstream proxy. Use a single SOCKS5 or HTTP upstream")
	}

	node, err := parseProxyURL(route.ChainNodes[0])
	if err != nil {
		return nil, err
	}

	switch node.Scheme {
	case "socks", "socks5":
		return json.Marshal(singBoxSocksOutbound{
			Type:       "socks",
			Tag:        "proxy",
			Server:     node.Host,
			ServerPort: node.Port,
			Version:    "5",
			Username:   node.Username,
			Password:   node.Password,
		})
	case "socks4", "socks4a":
		return json.Marshal(singBoxSocksOutbound{
			Type:       "socks",
			Tag:        "proxy",
			Server:     node.Host,
			ServerPort: node.Port,
			Version:    "4",
			Username:   node.Username,
			Password:   node.Password,
		})
	case "http", "https":
		return json.Marshal(singBoxHTTPOutbound{
			Type:       "http",
			Tag:        "proxy",
			Server:     node.Host,
			ServerPort: node.Port,
			Username:   node.Username,
			Password:   node.Password,
		})
	default:
		return nil, fmt.Errorf("VPN mode supports SOCKS5/SOCKS4/HTTP upstreams, got %q", node.Scheme)
	}
}

type parsedProxyURL struct {
	Scheme   string
	Host     string
	Port     uint16
	Username string
	Password string
}

func parseProxyURL(raw string) (parsedProxyURL, error) {
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return parsedProxyURL{}, err
	}
	if u.Scheme == "" {
		return parsedProxyURL{}, fmt.Errorf("missing proxy scheme in %q", raw)
	}

	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		return parsedProxyURL{}, fmt.Errorf("invalid proxy address %q: %w", u.Host, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return parsedProxyURL{}, fmt.Errorf("invalid proxy port %q: %w", portText, err)
	}

	parsed := parsedProxyURL{
		Scheme: strings.ToLower(u.Scheme),
		Host:   host,
		Port:   uint16(port),
	}
	if u.User != nil {
		parsed.Username = u.User.Username()
		parsed.Password, _ = u.User.Password()
	}
	return parsed, nil
}

func vpnRuntimeDir() (string, error) {
	storePath, err := profileStorePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(storePath), "vpn"), nil
}

func vpnStatePath() (string, error) {
	dir, err := vpnRuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, vpnStateFile), nil
}

func saveVPNState(state vpnRuntimeState) error {
	path, err := vpnStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func loadVPNState() (vpnRuntimeState, error) {
	path, err := vpnStatePath()
	if err != nil {
		return vpnRuntimeState{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return vpnRuntimeState{}, err
	}
	var state vpnRuntimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return vpnRuntimeState{}, err
	}
	return state, nil
}

func clearVPNState() error {
	path, err := vpnStatePath()
	if err != nil {
		return err
	}
	if state, err := loadVPNState(); err == nil && state.ConfigPath != "" {
		_ = os.Remove(state.ConfigPath)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func clearVPNStateIfPID(pid int) {
	state, err := loadVPNState()
	if err != nil || state.PID != pid {
		return
	}
	_ = clearVPNState()
}

func vpnModeRunning() (bool, vpnRuntimeState) {
	state, err := loadVPNState()
	if err != nil {
		return false, vpnRuntimeState{}
	}
	if !processMatches(state.PID, state.Executable) {
		_ = clearVPNState()
		return false, vpnRuntimeState{}
	}
	return true, state
}

func checkSingBoxConfig(singBoxPath string, configPath string) error {
	cmd := exec.Command(singBoxPath, "check", "-c", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box config check failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func findSingBox() (string, error) {
	if path := os.Getenv("GOST_SING_BOX"); path != "" {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
		return "", fmt.Errorf("GOST_SING_BOX points to a missing executable: %s", path)
	}

	var embeddedErr error
	if path, err := ensureEmbeddedSingBox(); err == nil && path != "" {
		return path, nil
	} else if err != nil {
		embeddedErr = err
	}

	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "sing-box.exe"),
			filepath.Join(dir, "bin", "sing-box.exe"),
			filepath.Join(dir, "sing-box"),
			filepath.Join(dir, "bin", "sing-box"),
		)
	}
	candidates = append(candidates,
		filepath.Join("C:\\", "tools", "gost", "bin", "sing-box.exe"),
		filepath.Join("C:\\", "tools", "sing-box", "sing-box.exe"),
	)

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	for _, name := range []string{"sing-box", "sing-box.exe"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	if embeddedErr != nil {
		return "", fmt.Errorf("embedded sing-box could not be prepared: %w", embeddedErr)
	}
	return "", errors.New("sing-box executable not found. Put sing-box.exe in C:\\tools\\gost\\bin or set GOST_SING_BOX")
}

func profileSlug(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	re := regexp.MustCompile(`[^a-z0-9._-]+`)
	name = strings.Trim(re.ReplaceAllString(name, "-"), "-")
	if name == "" {
		return "profile"
	}
	return name
}
