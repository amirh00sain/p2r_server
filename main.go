package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	showToken := flag.Bool("print-token", false, "print the primary token and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(Version)
		return
	}

	cfg, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fatal] config: %v\n", err)
		os.Exit(1)
	}

	log := NewLogger(cfg.PanelLogLines, cfg.Verbose)
	users, err := NewUserStore(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fatal] token store: %v\n", err)
		os.Exit(1)
	}

	staticKey, err := loadOrCreateServerStaticKey(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fatal] secure static key: %v\n", err)
		os.Exit(1)
	}

	if *showToken {
		fmt.Println(users.Primary())
		return
	}

	srv := NewServer(cfg, log, users, staticKey)
	log.Infof("Spider WSS Tunnel server v%s starting", Version)
	log.Infof("credential store: %s (%d token(s))", users.Path(), users.Count())
	log.Infof("generated fresh primary token for this run")
	log.Infof("primary token: %s", users.Primary())
	log.Infof("SPIDER-SEC-1 server public key: %s", encodeServerPublicKey(staticKey.PublicKey()))
	log.Infof("web panel:   http://0.0.0.0:%s/  (HTTP Basic: admin / %s)", cfg.Port, panelAuthSummary(cfg.PanelPassword))
	log.Infof("tunnel endpoint: ws://0.0.0.0:%s/ws  (token stays inside SPIDER-SEC-1)", cfg.Port)

	mux := http.NewServeMux()
	// /ws is an unauthenticated HTTP upgrade; SPIDER-SEC-1 authenticates inside the WebSocket.
	// The dashboard and its API require HTTP Basic (admin / PANEL_PASSWORD).
	mux.HandleFunc("/ws", srv.handleWS)
	mux.HandleFunc("/", srv.panelAuth(srv.servePanel))
	mux.HandleFunc("/api/stats", srv.panelAuth(srv.serveStats))
	mux.HandleFunc("/api/logs", srv.panelAuth(srv.serveLogs))
	mux.HandleFunc("/api/rotate", srv.panelAuth(srv.serveRotate))
	mux.HandleFunc("/api/token", srv.panelAuth(srv.serveToken))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"status":   "ok",
			"version":  cfg.Version,
			"clients":  srv.ActiveClients(),
			"sessions": srv.ActiveSessions(),
			"uptime_s": int64(time.Since(startTime).Seconds()),
		})
	})

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           recoverMiddleware(recoverMiddlewareLog(srv.log)(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          stdlog.New(os.Stderr, "[http] ", stdlog.LstdFlags),
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		log.Errorf("listen on %s failed: %v", cfg.Addr, err)
		os.Exit(1)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Infof("received %s, draining for up to %s", sig, cfg.ShutdownTimeout)
	case err := <-errCh:
		log.Errorf("http server failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Errorf("shutdown: %v", err)
	}
	log.Infof("stopped cleanly; %d session(s) closed", srv.ActiveSessions())
}

// panelAuthSummary renders the panel credential hint for the startup log.
func panelAuthSummary(password string) string {
	if password == "" {
		return "(disabled)"
	}
	return password
}

// recoverMiddleware converts panics in handlers into 500s instead of killing
// the process.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				fmt.Fprintf(os.Stderr, "[panic] %v\n", rec)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// recoverMiddlewareLog logs panics through the panel-aware logger.
func recoverMiddlewareLog(log *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Errorf("panic in %s %s: %v", r.Method, r.URL.Path, rec)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// formatBytes renders a byte count with a human friendly unit.
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// formatUptime renders "3d 4h 5m" style uptime for the panel footer.
func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return strconv.Itoa(days) + "d " + strconv.Itoa(hours) + "h"
	}
	if hours > 0 {
		return strconv.Itoa(hours) + "h " + strconv.Itoa(mins) + "m"
	}
	return strconv.Itoa(mins) + "m"
}
