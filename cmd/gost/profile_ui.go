package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ginuerzh/gost"
)

const (
	profileStoreVersion = 1
	locationCheckURL    = "http://ip-api.com/json/?fields=status,message,country,regionName,city,query,isp"
)

var inputEOF bool

type profileStore struct {
	Version     int            `json:"version"`
	LastProfile string         `json:"lastProfile,omitempty"`
	Profiles    []proxyProfile `json:"profiles"`
}

type proxyProfile struct {
	Name      string              `json:"name"`
	Config    baseConfig          `json:"config"`
	LastCheck *profileCheckResult `json:"lastCheck,omitempty"`
	CreatedAt time.Time           `json:"createdAt"`
	UpdatedAt time.Time           `json:"updatedAt"`
}

type profileCheckResult struct {
	OK        bool      `json:"ok"`
	IP        string    `json:"ip,omitempty"`
	Country   string    `json:"country,omitempty"`
	Region    string    `json:"region,omitempty"`
	City      string    `json:"city,omitempty"`
	ISP       string    `json:"isp,omitempty"`
	LatencyMS int64     `json:"latencyMs,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

type locationResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Country string `json:"country"`
	Region  string `json:"regionName"`
	City    string `json:"city"`
	Query   string `json:"query"`
	ISP     string `json:"isp"`
}

func runProfileUI() error {
	reader := bufio.NewReader(os.Stdin)
	storePath, err := profileStorePath()
	if err != nil {
		return err
	}

	store, err := loadProfiles(storePath)
	if err != nil {
		return err
	}

	printGostBanner()
	fmt.Fprintf(os.Stdout, "Profiles: %s\n\n", storePath)

	for {
		printProfileMenu(store)
		choice := strings.ToLower(readLine(reader, "gost> "))

		switch choice {
		case "1", "list", "profiles":
			printProfiles(store)
		case "2", "select":
			if err := selectProfile(reader, store, storePath); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case "3", "add":
			if err := addProfile(reader, store, storePath); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case "4", "json":
			if err := importProfileJSON(reader, store, storePath); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case "5", "check":
			if err := checkSelectedProfile(reader, store, storePath); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case "6", "start", "run":
			return startSelectedProfile(reader, store)
		case "7", "update", "edit":
			if err := updateProfile(reader, store, storePath); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case "8", "delete", "del":
			if err := deleteProfile(reader, store, storePath); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case "9", "system", "enable-system":
			if err := startSelectedProfileWithSystemProxy(reader, store); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case "10", "disable-system":
			if err := disableSystemProxy(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				fmt.Fprintln(os.Stdout, "System proxy disabled.")
			}
		case "11", "help", "?":
			flag.PrintDefaults()
			fmt.Fprintln(os.Stdout)
			fmt.Fprintln(os.Stdout, "Profile node strings use the same syntax as -L and -F.")
			fmt.Fprintln(os.Stdout, "Use JSON import for the complete gost config surface: Routes, Debug, Mark, Interface, Retries and node query parameters.")
		case "q", "quit", "exit":
			return nil
		case "":
			if inputEOF {
				return nil
			}
		default:
			fmt.Fprintln(os.Stderr, "unknown command")
		}
	}
}

func printGostBanner() {
	fmt.Fprintln(os.Stdout, "   ______   ____    _____  ______")
	fmt.Fprintln(os.Stdout, "  / ____/  / __ \\  / ___/ /_  __/")
	fmt.Fprintln(os.Stdout, " / / __   / / / /  \\__ \\   / /")
	fmt.Fprintln(os.Stdout, "/ /_/ /  / /_/ /  ___/ /  / /")
	fmt.Fprintln(os.Stdout, "\\____/   \\____/  /____/  /_/")
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "GOST interactive proxy profiles")
	fmt.Fprintln(os.Stdout, "")
}

func printProfileMenu(store *profileStore) {
	selected := store.LastProfile
	if selected == "" {
		selected = "<none>"
	}
	fmt.Fprintf(os.Stdout, "Selected: %s\n", selected)
	fmt.Fprintln(os.Stdout, "1) profiles")
	fmt.Fprintln(os.Stdout, "2) select profile")
	fmt.Fprintln(os.Stdout, "3) add profile")
	fmt.Fprintln(os.Stdout, "4) import/update profile from JSON config")
	fmt.Fprintln(os.Stdout, "5) check selected profile")
	fmt.Fprintln(os.Stdout, "6) start selected profile")
	fmt.Fprintln(os.Stdout, "7) update profile")
	fmt.Fprintln(os.Stdout, "8) delete profile")
	fmt.Fprintln(os.Stdout, "9) enable system proxy and start selected profile")
	fmt.Fprintln(os.Stdout, "10) disable system proxy")
	fmt.Fprintln(os.Stdout, "11) help")
	fmt.Fprintln(os.Stdout, "q) quit")
}

func printProfiles(store *profileStore) {
	if len(store.Profiles) == 0 {
		fmt.Fprintln(os.Stdout, "No profiles yet.")
		return
	}

	fmt.Fprintln(os.Stdout, "#  Name                 Listen                         Forward                        Check")
	for i := range store.Profiles {
		p := &store.Profiles[i]
		marker := " "
		if p.Name == store.LastProfile {
			marker = "*"
		}
		fmt.Fprintf(os.Stdout, "%s%-2d %-20s %-30s %-30s %s\n",
			marker,
			i+1,
			truncate(p.Name, 20),
			truncate(strings.Join(p.Config.route.ServeNodes, ","), 30),
			truncate(strings.Join(p.Config.route.ChainNodes, ","), 30),
			formatCheck(p.LastCheck),
		)
	}
}

func addProfile(reader *bufio.Reader, store *profileStore, storePath string) error {
	name := readRequiredLine(reader, "Profile name: ")
	if name == "" {
		return errors.New("profile name is required")
	}
	if findProfile(store, name) >= 0 {
		return fmt.Errorf("profile %q already exists", name)
	}

	cfg := baseConfig{}
	cfg.route.ServeNodes = readNodeList(reader, localServiceHelp())
	cfg.route.ChainNodes = readNodeList(reader, upstreamProxyHelp())
	if readBool(reader, "Show advanced settings? [y/N]: ") {
		cfg.route.Retries = readInt(reader, "Connection retries (0 = default): ", 0)
		cfg.route.Mark = readInt(reader, "SO_MARK for Linux policy routing (0 = disabled): ", 0)
		cfg.route.Interface = readLine(reader, "Outbound network interface (empty = any): ")
		cfg.Debug = readBool(reader, "Enable debug logging? [y/N]: ")
	}

	if len(cfg.route.ServeNodes) == 0 {
		return errors.New("at least one listen node is required")
	}
	if _, err := cfg.route.parseChain(); err != nil {
		return fmt.Errorf("invalid forward chain: %w", err)
	}
	for _, node := range cfg.route.ServeNodes {
		if _, err := gost.ParseNode(node); err != nil {
			return fmt.Errorf("invalid listen node %q: %w", node, err)
		}
	}

	now := time.Now()
	store.Profiles = append(store.Profiles, proxyProfile{
		Name:      name,
		Config:    cfg,
		CreatedAt: now,
		UpdatedAt: now,
	})
	store.LastProfile = name
	return saveProfiles(storePath, store)
}

func importProfileJSON(reader *bufio.Reader, store *profileStore, storePath string) error {
	name := readRequiredLine(reader, "profile name: ")
	if name == "" {
		return errors.New("profile name is required")
	}

	path := readRequiredLine(reader, "path to gost JSON config: ")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var cfg baseConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if err := validateConfigForProfile(&cfg); err != nil {
		return err
	}

	now := time.Now()
	idx := findProfile(store, name)
	if idx < 0 {
		store.Profiles = append(store.Profiles, proxyProfile{
			Name:      name,
			Config:    cfg,
			CreatedAt: now,
			UpdatedAt: now,
		})
	} else {
		store.Profiles[idx].Config = cfg
		store.Profiles[idx].UpdatedAt = now
	}
	store.LastProfile = name
	return saveProfiles(storePath, store)
}

func selectProfile(reader *bufio.Reader, store *profileStore, storePath string) error {
	if len(store.Profiles) == 0 {
		return errors.New("no profiles")
	}

	for {
		printProfiles(store)
		value := readRequiredLine(reader, "select profile, or check with 'c <profile>': ")
		fields := strings.Fields(value)
		if len(fields) >= 2 && (strings.EqualFold(fields[0], "c") || strings.EqualFold(fields[0], "check")) {
			idx, err := profileIndexFromValue(store, strings.Join(fields[1:], " "))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			fmt.Fprintf(os.Stdout, "Checking %s...\n", store.Profiles[idx].Name)
			result := checkProfile(&store.Profiles[idx])
			store.Profiles[idx].LastCheck = &result
			store.Profiles[idx].UpdatedAt = time.Now()
			if err := saveProfiles(storePath, store); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, formatCheck(&result))
			continue
		}

		idx, err := profileIndexFromValue(store, value)
		if err != nil {
			return err
		}
		store.LastProfile = store.Profiles[idx].Name
		return saveProfiles(storePath, store)
	}
}

func checkSelectedProfile(reader *bufio.Reader, store *profileStore, storePath string) error {
	idx, err := selectedProfileIndex(reader, store)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Checking %s...\n", store.Profiles[idx].Name)
	result := checkProfile(&store.Profiles[idx])
	store.Profiles[idx].LastCheck = &result
	store.Profiles[idx].UpdatedAt = time.Now()
	if err := saveProfiles(storePath, store); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, formatCheck(&result))
	return nil
}

func updateProfile(reader *bufio.Reader, store *profileStore, storePath string) error {
	if len(store.Profiles) == 0 {
		return errors.New("no profiles")
	}

	printProfiles(store)
	idx, err := readProfileIndex(reader, store, "update profile: ")
	if err != nil {
		return err
	}

	profile := &store.Profiles[idx]
	cfg := *cloneBaseConfig(profile.Config)

	fmt.Fprintf(os.Stdout, "\nEditing %s\n", profile.Name)
	printNodeList("Current local service address", cfg.route.ServeNodes)
	if readBool(reader, "Replace local service address? [y/N]: ") {
		cfg.route.ServeNodes = readNodeList(reader, localServiceHelp())
	}

	printNodeList("Current upstream proxy", cfg.route.ChainNodes)
	if readBool(reader, "Replace upstream proxy? [y/N]: ") {
		cfg.route.ChainNodes = readNodeList(reader, upstreamProxyHelp())
	}

	if readBool(reader, "Update advanced settings? [y/N]: ") {
		cfg.route.Retries = readInt(reader, fmt.Sprintf("Connection retries [%d]: ", cfg.route.Retries), cfg.route.Retries)
		cfg.route.Mark = readInt(reader, fmt.Sprintf("SO_MARK for Linux policy routing [%d]: ", cfg.route.Mark), cfg.route.Mark)
		if value := readLine(reader, fmt.Sprintf("Outbound network interface [%s]: ", emptyAsAny(cfg.route.Interface))); value != "" {
			cfg.route.Interface = value
		}
		cfg.Debug = readBoolDefault(reader, fmt.Sprintf("Enable debug logging? [%s]: ", boolAsYN(cfg.Debug)), cfg.Debug)
	}

	if value := readLine(reader, fmt.Sprintf("New profile name [%s]: ", profile.Name)); value != "" {
		if existing := findProfile(store, value); existing >= 0 && existing != idx {
			return fmt.Errorf("profile %q already exists", value)
		}
		if store.LastProfile == profile.Name {
			store.LastProfile = value
		}
		profile.Name = value
	}

	if err := validateConfigForProfile(&cfg); err != nil {
		return err
	}

	profile.Config = cfg
	profile.LastCheck = nil
	profile.UpdatedAt = time.Now()
	store.LastProfile = profile.Name
	return saveProfiles(storePath, store)
}

func startSelectedProfile(reader *bufio.Reader, store *profileStore) error {
	idx, err := selectedProfileIndex(reader, store)
	if err != nil {
		return err
	}

	baseCfg = cloneBaseConfig(store.Profiles[idx].Config)
	fmt.Fprintf(os.Stdout, "Starting profile %s...\n", store.Profiles[idx].Name)
	return runServer()
}

func deleteProfile(reader *bufio.Reader, store *profileStore, storePath string) error {
	if len(store.Profiles) == 0 {
		return errors.New("no profiles")
	}
	printProfiles(store)
	idx, err := readProfileIndex(reader, store, "delete profile: ")
	if err != nil {
		return err
	}
	name := store.Profiles[idx].Name
	if !readBool(reader, fmt.Sprintf("delete %q? [y/N]: ", name)) {
		return nil
	}
	store.Profiles = append(store.Profiles[:idx], store.Profiles[idx+1:]...)
	if store.LastProfile == name {
		store.LastProfile = ""
		if len(store.Profiles) > 0 {
			store.LastProfile = store.Profiles[0].Name
		}
	}
	return saveProfiles(storePath, store)
}

func startSelectedProfileWithSystemProxy(reader *bufio.Reader, store *profileStore) error {
	idx, err := selectedProfileIndex(reader, store)
	if err != nil {
		return err
	}

	target, err := systemProxyTargetForProfile(&store.Profiles[idx])
	if err != nil {
		return err
	}

	baseCfg = cloneBaseConfig(store.Profiles[idx].Config)
	if err := setupServer(); err != nil {
		return err
	}
	if err := enableSystemProxy(target); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "System proxy enabled: %s\n", target.Display())
	fmt.Fprintf(os.Stdout, "Started profile %s. Keep this terminal open. Press Ctrl+C to stop GOST, then run 'gost' and choose 10 to disable system proxy.\n", store.Profiles[idx].Name)
	select {}
}

func selectedProfileIndex(reader *bufio.Reader, store *profileStore) (int, error) {
	if len(store.Profiles) == 0 {
		return -1, errors.New("no profiles")
	}
	if store.LastProfile != "" {
		if idx := findProfile(store, store.LastProfile); idx >= 0 {
			return idx, nil
		}
	}
	printProfiles(store)
	return readProfileIndex(reader, store, "select profile: ")
}

func readProfileIndex(reader *bufio.Reader, store *profileStore, prompt string) (int, error) {
	value := readRequiredLine(reader, prompt)
	return profileIndexFromValue(store, value)
}

func profileIndexFromValue(store *profileStore, value string) (int, error) {
	if value == "" {
		return -1, errors.New("profile selection is required")
	}
	if idx := findProfile(store, value); idx >= 0 {
		return idx, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > len(store.Profiles) {
		return -1, fmt.Errorf("invalid profile %q", value)
	}
	return n - 1, nil
}

func checkProfile(profile *proxyProfile) profileCheckResult {
	started := time.Now()
	result := profileCheckResult{CheckedAt: started}

	route := checkRoute(profile)
	chain, err := route.parseChain()
	if err != nil {
		result.Error = err.Error()
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return chain.DialContext(ctx, network, address, gost.TimeoutChainOption(10*time.Second))
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, locationCheckURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Sprintf("location service returned %s", resp.Status)
		return result
	}

	var loc locationResponse
	if err := json.Unmarshal(body, &loc); err != nil {
		result.Error = err.Error()
		return result
	}
	if loc.Status != "" && loc.Status != "success" {
		if loc.Message == "" {
			loc.Message = "location lookup failed"
		}
		result.Error = loc.Message
		return result
	}

	result.OK = true
	result.IP = loc.Query
	result.Country = loc.Country
	result.Region = loc.Region
	result.City = loc.City
	result.ISP = loc.ISP
	result.LatencyMS = time.Since(started).Milliseconds()
	return result
}

func checkRoute(profile *proxyProfile) route {
	if len(profile.Config.route.ChainNodes) > 0 {
		return profile.Config.route
	}
	for _, rt := range profile.Config.Routes {
		if len(rt.ChainNodes) > 0 {
			return rt
		}
	}
	return profile.Config.route
}

func localRoute(profile *proxyProfile) route {
	if len(profile.Config.route.ServeNodes) > 0 {
		return profile.Config.route
	}
	for _, rt := range profile.Config.Routes {
		if len(rt.ServeNodes) > 0 {
			return rt
		}
	}
	return profile.Config.route
}

func systemProxyTargetForProfile(profile *proxyProfile) (systemProxyTarget, error) {
	route := localRoute(profile)
	if len(route.ServeNodes) == 0 {
		return systemProxyTarget{}, errors.New("selected profile has no local service address")
	}

	node, err := gost.ParseNode(route.ServeNodes[0])
	if err != nil {
		return systemProxyTarget{}, err
	}

	addr, err := normalizeProxyAddress(node.Addr)
	if err != nil {
		return systemProxyTarget{}, err
	}

	mode := "http"
	switch node.Protocol {
	case "socks", "socks5", "socks4", "socks4a":
		return systemProxyTarget{}, errors.New("Windows system proxy needs an HTTP local service. Update Local service address to http://127.0.0.1:8080 or :8080; keep Webshare in Upstream proxy")
	case "":
		mode = "http"
	case "http", "http2":
		mode = "http"
	default:
		return systemProxyTarget{}, fmt.Errorf("system proxy can use only HTTP or SOCKS local services, got %q", node.Protocol)
	}

	return systemProxyTarget{
		Mode: mode,
		Addr: addr,
	}, nil
}

func normalizeProxyAddress(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid local service address %q: %w", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("invalid local service address %q: missing port", addr)
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

func validateConfigForProfile(cfg *baseConfig) error {
	if len(cfg.route.ServeNodes) == 0 && len(cfg.Routes) == 0 {
		return errors.New("config must contain ServeNodes or Routes")
	}
	if _, err := cfg.route.parseChain(); err != nil {
		return err
	}
	for _, node := range cfg.route.ServeNodes {
		if _, err := gost.ParseNode(node); err != nil {
			return err
		}
	}
	for i := range cfg.Routes {
		if _, err := cfg.Routes[i].parseChain(); err != nil {
			return err
		}
		for _, node := range cfg.Routes[i].ServeNodes {
			if _, err := gost.ParseNode(node); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadProfiles(path string) (*profileStore, error) {
	store := &profileStore{Version: profileStoreVersion}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}
	if store.Version == 0 {
		store.Version = profileStoreVersion
	}
	return store, nil
}

func saveProfiles(path string, store *profileStore) error {
	store.Version = profileStoreVersion
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func profileStorePath() (string, error) {
	if path := os.Getenv("GOST_PROFILES"); path != "" {
		return path, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			if err != nil {
				return "", err
			}
			return "", homeErr
		}
		dir = filepath.Join(home, ".gost")
	} else {
		dir = filepath.Join(dir, "gost")
	}
	return filepath.Join(dir, "profiles.json"), nil
}

func cloneBaseConfig(cfg baseConfig) *baseConfig {
	clone := cfg
	clone.route.ServeNodes = append(stringList(nil), cfg.route.ServeNodes...)
	clone.route.ChainNodes = append(stringList(nil), cfg.route.ChainNodes...)
	if len(cfg.Routes) > 0 {
		clone.Routes = make([]route, len(cfg.Routes))
		copy(clone.Routes, cfg.Routes)
		for i := range clone.Routes {
			clone.Routes[i].ServeNodes = append(stringList(nil), cfg.Routes[i].ServeNodes...)
			clone.Routes[i].ChainNodes = append(stringList(nil), cfg.Routes[i].ChainNodes...)
		}
	}
	return &clone
}

func findProfile(store *profileStore, name string) int {
	for i := range store.Profiles {
		if strings.EqualFold(store.Profiles[i].Name, name) {
			return i
		}
	}
	return -1
}

func readNodeList(reader *bufio.Reader, label string) stringList {
	var nodes stringList
	fmt.Fprintln(os.Stdout, label)
	for {
		value := readLine(reader, "> ")
		if value == "" {
			return nodes
		}
		nodes = append(nodes, value)
	}
}

func printNodeList(label string, nodes stringList) {
	fmt.Fprintln(os.Stdout, label+":")
	if len(nodes) == 0 {
		fmt.Fprintln(os.Stdout, "  <empty>")
		return
	}
	for _, node := range nodes {
		fmt.Fprintln(os.Stdout, "  "+node)
	}
}

func localServiceHelp() string {
	return "\nLocal service address. This is the same value you would pass with -L.\nExamples:\n  :8080                         HTTP/SOCKS5 proxy on port 8080\n  socks5://127.0.0.1:1080       SOCKS5 proxy on 127.0.0.1:1080\n  tcp://:2222/192.168.1.10:22   TCP port forwarding\nEnter one or more lines. Empty line finishes this section."
}

func upstreamProxyHelp() string {
	return "\nUpstream proxy. This is the same value you would pass with -F. Leave it empty for direct connection.\nExamples:\n  socks5://host:1080\n  socks5://user:pass@host:1080\n  http://user:pass@host:8080\n  ss://method:pass@host:8388\nMultiple lines create a proxy chain. Empty line finishes this section."
}

func readRequiredLine(reader *bufio.Reader, prompt string) string {
	return strings.TrimSpace(readLine(reader, prompt))
}

func readLine(reader *bufio.Reader, prompt string) string {
	fmt.Fprint(os.Stdout, prompt)
	value, err := reader.ReadString('\n')
	if errors.Is(err, io.EOF) && value == "" {
		inputEOF = true
		return ""
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	return strings.TrimSpace(value)
}

func readInt(reader *bufio.Reader, prompt string, fallback int) int {
	value := readLine(reader, prompt)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func readBool(reader *bufio.Reader, prompt string) bool {
	value := strings.ToLower(readLine(reader, prompt))
	return value == "y" || value == "yes" || value == "\u0434" || value == "\u0434\u0430" || value == "true" || value == "1"
}

func readBoolDefault(reader *bufio.Reader, prompt string, fallback bool) bool {
	value := strings.ToLower(readLine(reader, prompt))
	if value == "" {
		return fallback
	}
	return value == "y" || value == "yes" || value == "true" || value == "1"
}

func emptyAsAny(value string) string {
	if value == "" {
		return "any"
	}
	return value
}

func boolAsYN(value bool) string {
	if value {
		return "Y"
	}
	return "N"
}

func formatCheck(check *profileCheckResult) string {
	if check == nil {
		return "not checked"
	}
	if !check.OK {
		return "failed: " + check.Error
	}
	parts := []string{}
	if check.IP != "" {
		parts = append(parts, check.IP)
	}
	location := strings.Trim(strings.Join([]string{check.City, check.Region, check.Country}, ", "), ", ")
	if location != "" {
		parts = append(parts, location)
	}
	if check.ISP != "" {
		parts = append(parts, check.ISP)
	}
	parts = append(parts, fmt.Sprintf("%dms", check.LatencyMS))
	return strings.Join(parts, " | ")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
