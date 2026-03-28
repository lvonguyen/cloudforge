package terminal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"aegis/internal/api"
	"aegis/internal/audit"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	pingInterval    = 25 * time.Second
	pongWait        = 10 * time.Second
	writeWait       = 10 * time.Second
	idleTimeout     = 5 * time.Minute
	maxMessageSize  = 4096
	maxSessionsUser = 2
)

// ClientMessage is a command sent from the frontend.
type ClientMessage struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Command string `json:"command,omitempty"`
}

// ServerMessage is sent back to the frontend.
type ServerMessage struct {
	Type      string `json:"type"`
	ID        string `json:"id,omitempty"`
	Stream    string `json:"stream,omitempty"`
	Data      string `json:"data,omitempty"`
	Code      *int   `json:"code,omitempty"`
	ElapsedMs *int64 `json:"elapsed_ms,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Handler upgrades HTTP to WebSocket for interactive terminal sessions.
type Handler struct {
	upgrader       websocket.Upgrader
	executor       *Executor
	authMW         *api.AuthMiddleware
	auditLogger    audit.AuditLogger
	logger         *zap.Logger
	allowedOrigins []string
	devMode        bool
	tickets        *TicketStore

	// Per-user session tracking.
	mu       sync.Mutex
	sessions map[string]int // subject -> active session count
}

// NewHandler creates a terminal WebSocket handler.
func NewHandler(authMW *api.AuthMiddleware, auditLogger audit.AuditLogger, logger *zap.Logger, devMode bool, allowedOrigins ...string) *Handler {
	h := &Handler{
		executor:       NewExecutor(logger),
		authMW:         authMW,
		auditLogger:    auditLogger,
		logger:         logger,
		allowedOrigins: allowedOrigins,
		devMode:        devMode,
		tickets:        NewTicketStore(logger),
		sessions:       make(map[string]int),
	}
	h.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin:     h.checkOrigin,
	}
	return h
}

// checkOrigin validates the WebSocket origin against the allowlist.
func (h *Handler) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	// Allow localhost only in development mode.
	if h.devMode && (strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1")) {
		return true
	}
	for _, allowed := range h.allowedOrigins {
		if origin == allowed {
			return true
		}
	}
	h.logger.Warn("terminal: origin rejected", zap.String("origin", origin))
	return false
}

// IssueTicket is an HTTP handler for POST /api/v1/terminal/ticket.
// It validates the JWT from the Authorization header, checks RBAC, and returns
// a short-lived, one-time-use ticket for WebSocket authentication (SA-002).
func (h *Handler) IssueTicket(w http.ResponseWriter, r *http.Request) {
	// Extract JWT from Authorization header.
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
		return
	}
	raw := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := h.authMW.ValidateTokenString(raw)
	if err != nil {
		h.logger.Warn("terminal: ticket auth failed", zap.Error(err), zap.String("remote_addr", r.RemoteAddr))
		http.Error(w, `{"error":"authentication failed"}`, http.StatusUnauthorized)
		return
	}

	// RBAC: require operator or admin.
	role := api.RoleFromClaims(claims)
	if role != api.RoleOperator && role != api.RoleAdmin {
		http.Error(w, `{"error":"forbidden: operator or admin role required"}`, http.StatusForbidden)
		return
	}

	ticket, err := h.tickets.Issue(claims.Subject, role, claims.Groups)
	if err != nil {
		h.logger.Error("terminal: ticket issue failed", zap.Error(err))
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"ticket": ticket})
}

// ServeHTTP handles the WebSocket upgrade with ticket or JWT auth.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var subject string
	var role api.Role
	var claims *api.Claims

	// SA-002: prefer ?ticket= (one-time nonce), fall back to ?token= (legacy JWT).
	if ticket := r.URL.Query().Get("ticket"); ticket != "" {
		sub, rl, groups, err := h.tickets.Consume(ticket)
		if err != nil {
			h.logger.Warn("terminal: ticket auth failed", zap.Error(err), zap.String("remote_addr", r.RemoteAddr))
			http.Error(w, `{"error":"invalid or expired ticket"}`, http.StatusUnauthorized)
			return
		}
		subject = sub
		role = rl
		claims = &api.Claims{Subject: sub, Groups: groups}
	} else if token := r.URL.Query().Get("token"); token != "" {
		// Legacy path: JWT in query parameter (backward compatibility).
		c, err := h.authMW.ValidateTokenString(token)
		if err != nil {
			h.logger.Warn("terminal: auth failed", zap.Error(err), zap.String("remote_addr", r.RemoteAddr))
			http.Error(w, `{"error":"authentication failed"}`, http.StatusUnauthorized)
			return
		}
		claims = c
		subject = c.Subject
		role = api.RoleFromClaims(c)

		if role != api.RoleOperator && role != api.RoleAdmin {
			h.logger.Warn("terminal: insufficient role",
				zap.String("subject", claims.Subject),
				zap.String("role", string(role)),
			)
			http.Error(w, `{"error":"forbidden: operator or admin role required"}`, http.StatusForbidden)
			return
		}
	} else {
		http.Error(w, `{"error":"missing ticket or token parameter"}`, http.StatusUnauthorized)
		return
	}

	// Enforce per-user session limit.
	h.mu.Lock()
	if h.sessions[subject] >= maxSessionsUser {
		h.mu.Unlock()
		http.Error(w, `{"error":"too many active terminal sessions"}`, http.StatusTooManyRequests)
		return
	}
	h.sessions[subject]++
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		h.sessions[subject]--
		if h.sessions[subject] <= 0 {
			delete(h.sessions, subject)
		}
		h.mu.Unlock()
	}()

	// Upgrade to WebSocket.
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("terminal: upgrade failed", zap.Error(err))
		return
	}
	defer conn.Close()

	// Audit: connection established.
	h.logAudit(r, claims, role, audit.ActionTerminalConnect, "", audit.ResultSuccess)

	h.logger.Info("terminal: session started",
		zap.String("subject", claims.Subject),
		zap.String("role", string(role)),
		zap.String("remote_addr", r.RemoteAddr),
	)

	// Configure connection limits.
	conn.SetReadLimit(maxMessageSize)

	// Wrap connection with write mutex to prevent concurrent writes.
	wc := &wsConn{Conn: conn}

	// Connection-scoped context for cancelling child processes on disconnect.
	connCtx, connCancel := context.WithCancel(r.Context())
	defer connCancel()

	// Start ping/pong keepalive.
	done := make(chan struct{})
	go h.pingLoop(wc, done)

	h.readLoop(connCtx, wc, r, claims, role, done)
}

// wsConn wraps a websocket.Conn with a write mutex for gorilla/websocket safety.
// gorilla/websocket supports one concurrent reader and one concurrent writer.
type wsConn struct {
	*websocket.Conn
	mu sync.Mutex
}

func (wc *wsConn) writeJSON(v interface{}) error {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if err := wc.Conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return err
	}
	return wc.Conn.WriteJSON(v)
}

func (h *Handler) readLoop(connCtx context.Context, wc *wsConn, r *http.Request, claims *api.Claims, role api.Role, done chan struct{}) {
	defer close(done)

	for {
		// Set read deadline for idle timeout.
		if err := wc.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}

		_, msgBytes, err := wc.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				h.logger.Warn("terminal: read error", zap.Error(err))
			}
			return
		}

		var msg ClientMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			h.sendError(wc, "", "invalid message format")
			continue
		}

		switch msg.Type {
		case "execute":
			h.handleExecute(connCtx, wc, r, claims, role, msg)
		case "pong":
			// Client responded to ping — connection is alive.
		default:
			h.sendError(wc, msg.ID, fmt.Sprintf("unknown message type: %s", msg.Type))
		}
	}
}

func (h *Handler) handleExecute(connCtx context.Context, wc *wsConn, r *http.Request, claims *api.Claims, role api.Role, msg ClientMessage) {
	binary, args, err := h.executor.Validate(msg.Command)
	if err != nil {
		h.logAudit(r, claims, role, audit.ActionTerminalDenied, msg.Command, audit.ResultDenied)
		h.sendError(wc, msg.ID, err.Error())
		return
	}

	// Execute with connection-scoped context so disconnect cancels child processes.
	result, execErr := h.executor.Execute(connCtx, binary, args)
	if execErr != nil {
		h.logAudit(r, claims, role, audit.ActionTerminalExecute, msg.Command, audit.ResultError)
		h.sendError(wc, msg.ID, "command execution failed")
		h.logger.Warn("terminal: execution failed", zap.Error(execErr), zap.String("command", binary))
		return
	}

	// Stream stdout.
	if result.Stdout != "" {
		h.sendMessage(wc, ServerMessage{
			Type:   "output",
			ID:     msg.ID,
			Stream: "stdout",
			Data:   result.Stdout,
		})
	}

	// Stream stderr.
	if result.Stderr != "" {
		h.sendMessage(wc, ServerMessage{
			Type:   "output",
			ID:     msg.ID,
			Stream: "stderr",
			Data:   result.Stderr,
		})
	}

	// Send exit message.
	code := result.ExitCode
	elapsed := result.ElapsedMs
	h.sendMessage(wc, ServerMessage{
		Type:      "exit",
		ID:        msg.ID,
		Code:      &code,
		ElapsedMs: &elapsed,
	})

	// Audit: command executed.
	auditResult := audit.ResultSuccess
	if result.ExitCode != 0 {
		auditResult = audit.ResultError
	}
	h.logAudit(r, claims, role, audit.ActionTerminalExecute, msg.Command, auditResult)
}

func (h *Handler) pingLoop(wc *wsConn, done <-chan struct{}) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			h.sendMessage(wc, ServerMessage{Type: "ping"})
		}
	}
}

func (h *Handler) sendMessage(wc *wsConn, msg ServerMessage) {
	if err := wc.writeJSON(msg); err != nil {
		h.logger.Warn("terminal: write error", zap.Error(err))
	}
}

func (h *Handler) sendError(wc *wsConn, id, message string) {
	h.sendMessage(wc, ServerMessage{
		Type:    "error",
		ID:      id,
		Message: message,
	})
}

func (h *Handler) logAudit(r *http.Request, claims *api.Claims, role api.Role, action, resource, result string) {
	if h.auditLogger == nil {
		return
	}

	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	entry := audit.AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     claims.Subject,
		ActorRole: string(role),
		Action:    action,
		Resource:  "terminal",
		Result:    result,
		IP:        ip,
	}
	if resource != "" {
		entry.ResourceID = resource
	}

	if err := h.auditLogger.Log(r.Context(), entry); err != nil {
		h.logger.Error("terminal: audit log failed", zap.Error(err))
	}
}
