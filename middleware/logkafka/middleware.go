package logkafka

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

type LogEntry struct {
	Level     string            `json:"level"`
	Module    string            `json:"module"`
	Message   string            `json:"message"`
	TraceID   string            `json:"trace_id"`
	Env       string            `json:"env"`
	Timestamp string            `json:"timestamp"`
	Extra     map[string]string `json:"extra"`
}

func LogToKafka(level, module, message, traceID, env string, extra map[string]string) {
	entry := LogEntry{
		Level:     level,
		Module:    module,
		Message:   message,
		TraceID:   traceID,
		Env:       env,
		Timestamp: time.Now().Format(time.RFC3339),
		Extra:     extra,
	}
	b, _ := json.Marshal(entry)
	_ = WriteLogToKafka(context.Background(), b)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		traceID := r.Header.Get("X-Trace-ID")
		if traceID == "" {
			traceID = uuid.New().String()
		}
		userID := r.Header.Get("X-User-ID")
		if userID == "" {
			userID = "anonymous"
		}
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		} else {
			ips := strings.Split(ip, ",")
			ip = strings.TrimSpace(ips[0])
		}

		rw := newResponseWriter(w)
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		extra := map[string]string{
			"user_id":     userID,
			"ip":          ip,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      fmt.Sprintf("%d", rw.statusCode),
			"duration_ms": fmt.Sprintf("%d", duration.Milliseconds()),
			"user_agent":  r.UserAgent(),
		}

		LogToKafka(
			"info",
			"http",
			"request completed",
			traceID,
			os.Getenv("APP_ENV"),
			extra,
		)
	})
}
