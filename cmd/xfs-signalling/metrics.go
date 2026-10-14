package main

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

func validateMetricsListen(addr string) error {
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("metrics listener: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("metrics listener requires an explicit loopback IP")
	}
	return nil
}

func metricsServer(addr string, handler http.Handler) (*http.Server, net.Listener, error) {
	if err := validateMetricsListen(addr); err != nil {
		return nil, nil, err
	}
	if addr == "" {
		return nil, nil, nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 4096}, listener, nil
}
