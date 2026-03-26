package terminal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
	upgrader    websocket.Upgrader
	executor    *Executor
	authMW      *api.AuthMiddleware
	auditLogger audit.AuditLogger
	logger      *zap.Logger

	// Per-user session tracking.
	mu       sync.Mutex
	sessions map[string]int // subject -> active session count
}

// NewHandler creates a terminal WebSocket handler.
func NewHandler(authMW *api.AuthMiddleware, auditLogger audit.AuditLogger, logger *zap.Logger) *Handler {
	return &Handler{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			CheckOrigin:     func(r *http.Request) bool { return true }, // CORS handled upstream.
		},
		executor:    NewExecutor(logger),
		authMW:      authMW,
		auditLogger: auditLogger,
		logger:      logger,
		sessions:    make(map[string]int),
	}
}

// ServeHTTP handles the WebSocket upgrade with manual JWT auth.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract token from query parameter (WS API cannot send custom headers).
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, `{"error":"missing token parameter"}`, http.StatusUnauthorized)
		return
	}

	// Validate JWT.
	claims, err := h.authMW.ValidateTokenString(token)
	if err != nil {
		h.logger.Warn("terminal: auth failed", zap.Error(err), zap.String("remote_addr", r.RemoteAddr))
		http.Error(w, `{"error":"authentication failed"}`, http.StatusUnauthorized)
		return
	}

	// RBAC: require operator or admin.
	role := api.RoleFromClaims(claims)
	if role != api.RoleOperator && role != api.RoleAdmin {
		h.logger.Warn("terminal: insufficient role",
			zap.String("subject", claims.Subject),
			zap.String("role", string(role)),
		)
		http.Error(w, `{"error":"forbidden: operator or admin role required"}`, http.StatusForbidden)
		return
	}

	// Enforce per-user session limit.
	h.mu.Lock()
	if h.sessions[claims.Subject] >= maxSessionsUser {
		h.mu.Unlock()
		http.Error(w, `{"error":"too many active terminal sessions"}`, http.StatusTooManyRequests)
		return
	}
	h.sessions[claims.Subject]++
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		h.sessions[claims.Subject]--
		if h.sessions[claims.Subject] <= 0 {
			delete(h.sessions, claims.Subject)
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

	// Start ping/pong keepalive.
	done := make(chan struct{})
	go h.pingLoop(conn, done)

	h.readLoop(conn, r, claims, role, done)
}

func (h *Handler) readLoop(conn *websocket.Conn, r *http.Request, claims *api.Claims, role api.Role, done chan struct{}) {
	defer close(done)

	idleTimer := time.NewTimer(idleTimeout)
	defer idleTimer.Stop()

	for {
		// Set read deadline for idle timeout.
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}

		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				h.logger.Warn("terminal: read error", zap.Error(err))
			}
			return
		}

		idleTimer.Reset(idleTimeout)

		var msg ClientMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			h.sendError(conn, "", "invalid message format")
			continue
		}

		switch msg.Type {
		case "execute":
			h.handleExecute(conn, r, claims, role, msg)
		case "pong":
			// Client responded to ping — connection is alive.
		default:
			h.sendError(conn, msg.ID, fmt.Sprintf("unknown message type: %s", msg.Type))
		}
	}
}

func (h *Handler) handleExecute(conn *websocket.Conn, r *http.Request, claims *api.Claims, role api.Role, msg ClientMessage) {
	binary, args, err := h.executor.Validate(msg.Command)
	if err != nil {
		h.logAudit(r, claims, role, audit.ActionTerminalDenied, msg.Command, audit.ResultDenied)
		h.sendError(conn, msg.ID, err.Error())
		return
	}

	// Execute the command.
	result, execErr := h.executor.Execute(context.Background(), binary, args)
	if execErr != nil {
		h.logAudit(r, claims, role, audit.ActionTerminalExecute, msg.Command, audit.ResultError)
		h.sendError(conn, msg.ID, fmt.Sprintf("execution failed: %v", execErr))
		return
	}

	// Stream stdout.
	if result.Stdout != "" {
		h.sendMessage(conn, ServerMessage{
			Type:   "output",
			ID:     msg.ID,
			Stream: "stdout",
			Data:   result.Stdout,
		})
	}

	// Stream stderr.
	if result.Stderr != "" {
		h.sendMessage(conn, ServerMessage{
			Type:   "output",
			ID:     msg.ID,
			Stream: "stderr",
			Data:   result.Stderr,
		})
	}

	// Send exit message.
	code := result.ExitCode
	elapsed := result.ElapsedMs
	h.sendMessage(conn, ServerMessage{
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

func (h *Handler) pingLoop(conn *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			h.sendMessage(conn, ServerMessage{Type: "ping"})
		}
	}
}

func (h *Handler) sendMessage(conn *websocket.Conn, msg ServerMessage) {
	if err := conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return
	}
	if err := conn.WriteJSON(msg); err != nil {
		h.logger.Warn("terminal: write error", zap.Error(err))
	}
}

func (h *Handler) sendError(conn *websocket.Conn, id, message string) {
	h.sendMessage(conn, ServerMessage{
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
