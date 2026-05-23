package main

import (
	"encoding/base64"
	"net/url"
	"strings"
)

const protectedNodePrefix = "gost-dpapi:"

func protectProfileStore(store *profileStore) (*profileStore, error) {
	clone := *store
	clone.Profiles = make([]proxyProfile, len(store.Profiles))
	for i := range store.Profiles {
		clone.Profiles[i] = store.Profiles[i]
		clone.Profiles[i].Config = *cloneBaseConfig(store.Profiles[i].Config)
		if err := protectBaseConfig(&clone.Profiles[i].Config); err != nil {
			return nil, err
		}
	}
	return &clone, nil
}

func unprotectProfileStore(store *profileStore) error {
	for i := range store.Profiles {
		if err := unprotectBaseConfig(&store.Profiles[i].Config); err != nil {
			return err
		}
	}
	return nil
}

func protectBaseConfig(cfg *baseConfig) error {
	var err error
	cfg.route.ServeNodes, err = protectNodeList(cfg.route.ServeNodes)
	if err != nil {
		return err
	}
	cfg.route.ChainNodes, err = protectNodeList(cfg.route.ChainNodes)
	if err != nil {
		return err
	}
	for i := range cfg.Routes {
		cfg.Routes[i].ServeNodes, err = protectNodeList(cfg.Routes[i].ServeNodes)
		if err != nil {
			return err
		}
		cfg.Routes[i].ChainNodes, err = protectNodeList(cfg.Routes[i].ChainNodes)
		if err != nil {
			return err
		}
	}
	return nil
}

func unprotectBaseConfig(cfg *baseConfig) error {
	var err error
	cfg.route.ServeNodes, err = unprotectNodeList(cfg.route.ServeNodes)
	if err != nil {
		return err
	}
	cfg.route.ChainNodes, err = unprotectNodeList(cfg.route.ChainNodes)
	if err != nil {
		return err
	}
	for i := range cfg.Routes {
		cfg.Routes[i].ServeNodes, err = unprotectNodeList(cfg.Routes[i].ServeNodes)
		if err != nil {
			return err
		}
		cfg.Routes[i].ChainNodes, err = unprotectNodeList(cfg.Routes[i].ChainNodes)
		if err != nil {
			return err
		}
	}
	return nil
}

func protectNodeList(nodes stringList) (stringList, error) {
	out := make(stringList, len(nodes))
	for i, node := range nodes {
		protected, err := protectNodeString(node)
		if err != nil {
			return nil, err
		}
		out[i] = protected
	}
	return out, nil
}

func unprotectNodeList(nodes stringList) (stringList, error) {
	out := make(stringList, len(nodes))
	for i, node := range nodes {
		unprotected, err := unprotectNodeString(node)
		if err != nil {
			return nil, err
		}
		out[i] = unprotected
	}
	return out, nil
}

func protectNodeString(node string) (string, error) {
	if strings.HasPrefix(node, protectedNodePrefix) || !nodeHasUserInfo(node) {
		return node, nil
	}
	protected, err := protectSecret([]byte(node))
	if err != nil {
		return "", err
	}
	return protectedNodePrefix + base64.RawURLEncoding.EncodeToString(protected), nil
}

func unprotectNodeString(node string) (string, error) {
	if !strings.HasPrefix(node, protectedNodePrefix) {
		return node, nil
	}
	encoded := strings.TrimPrefix(node, protectedNodePrefix)
	protected, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	plain, err := unprotectSecret(protected)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func nodeHasUserInfo(node string) bool {
	u, _, ok := parseNodeForSecret(node)
	return ok && u.User != nil
}

func displayNodeList(nodes stringList) string {
	masked := make([]string, len(nodes))
	for i, node := range nodes {
		masked[i] = maskNodeSecret(node)
	}
	return strings.Join(masked, ",")
}

func maskNodeSecret(node string) string {
	if strings.HasPrefix(node, protectedNodePrefix) {
		return "<encrypted>"
	}
	u, addedScheme, ok := parseNodeForSecret(node)
	if !ok || u.User == nil {
		return node
	}
	username := u.User.Username()
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(username, "****")
	} else {
		u.User = url.User(username)
	}
	masked := u.String()
	if addedScheme {
		return strings.TrimPrefix(masked, "socks5://")
	}
	return masked
}

func parseNodeForSecret(node string) (*url.URL, bool, bool) {
	if strings.Contains(node, "://") {
		u, err := url.Parse(node)
		return u, false, err == nil
	}
	u, err := url.Parse("socks5://" + node)
	return u, true, err == nil
}
