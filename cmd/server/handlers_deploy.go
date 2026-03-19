package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// DeployPreviewConfig matches the frontend DeployPreviewConfig type.
type DeployPreviewConfig struct {
	ResourceType  string                 `json:"resourceType"`
	Provider      string                 `json:"provider"`
	Region        string                 `json:"region"`
	AppID         string                 `json:"appId"`
	Configuration map[string]interface{} `json:"configuration"`
}

// deployExecution tracks a running deploy preview for abort support.
type deployExecution struct {
	cancel context.CancelFunc
}

// deployTracker manages active deploy preview executions.
type deployTracker struct {
	mu    sync.Mutex
	execs map[string]*deployExecution
}

func newDeployTracker() *deployTracker {
	return &deployTracker{execs: make(map[string]*deployExecution)}
}

func (dt *deployTracker) add(id string, cancel context.CancelFunc) {
	dt.mu.Lock()
	dt.execs[id] = &deployExecution{cancel: cancel}
	dt.mu.Unlock()
}

func (dt *deployTracker) abort(id string) bool {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if exec, ok := dt.execs[id]; ok {
		exec.cancel()
		delete(dt.execs, id)
		return true
	}
	return false
}

func (dt *deployTracker) remove(id string) {
	dt.mu.Lock()
	delete(dt.execs, id)
	dt.mu.Unlock()
}

// generateExecID creates a random execution ID for deploy previews.
func generateExecID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("exec-%d", time.Now().UnixNano())
	}
	return "exec-" + hex.EncodeToString(b)
}

// startDeployPreview handles POST /api/v1/deploy/preview.
// Starts a background deploy preview orchestration and returns the execution ID.
func (s *Server) startDeployPreview(w http.ResponseWriter, r *http.Request) {
	var config DeployPreviewConfig
	if !s.decodeJSONBody(w, r, &config) {
		return
	}

	if config.ResourceType == "" || config.Provider == "" || config.Region == "" {
		writeErrorResponse(w, "resourceType, provider, and region are required", http.StatusBadRequest)
		return
	}

	execID := generateExecID()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	s.deployTracker.add(execID, cancel)

	go s.runDeployPreview(ctx, execID, config)

	s.logAuditEvent(r, "deploy_preview.start", "deploy", execID, "accepted")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"execution_id": execID})
}

// abortDeployPreview handles POST /api/v1/deploy/preview/{id}/abort.
func (s *Server) abortDeployPreview(w http.ResponseWriter, r *http.Request) {
	execID := mux.Vars(r)["id"]
	if execID == "" {
		writeErrorResponse(w, "execution id required", http.StatusBadRequest)
		return
	}

	if !s.deployTracker.abort(execID) {
		writeErrorResponse(w, "execution not found or already completed", http.StatusNotFound)
		return
	}

	s.logAuditEvent(r, "deploy_preview.abort", "deploy", execID, "aborted")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "aborted"})
}

// runDeployPreview orchestrates the deploy preview, publishing SSE events to ws-server.
func (s *Server) runDeployPreview(ctx context.Context, execID string, config DeployPreviewConfig) {
	defer s.deployTracker.remove(execID)

	channel := "deploy:" + execID

	publish := func(event, message string, extra map[string]interface{}) {
		data := map[string]interface{}{"message": message}
		for k, v := range extra {
			data[k] = v
		}
		s.publishToWSServer(ctx, channel, event, data)
	}

	// Helper to check context cancellation between steps.
	cancelled := func() bool {
		return ctx.Err() != nil
	}

	sleep := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}

	// Phase 1: Planning
	publish("planning", "Initializing Terraform provider...", nil)
	if !sleep(800 * time.Millisecond) {
		return
	}

	publish("planning", fmt.Sprintf("Provider: %s | Region: %s", config.Provider, config.Region), nil)
	if !sleep(500 * time.Millisecond) {
		return
	}

	publish("planning", "Terraform v1.9.8 | Format 1.2", nil)
	if !sleep(600 * time.Millisecond) {
		return
	}

	isS3 := config.ResourceType == "s3"
	bucketName := fmt.Sprintf("cf-demo-%s-%d", config.AppID, time.Now().UnixMilli())

	if isS3 {
		publish("planning", "+ aws_s3_bucket.demo will be created", nil)
		if !sleep(400 * time.Millisecond) {
			return
		}
		publish("planning", "+ aws_s3_bucket_server_side_encryption_configuration.demo will be created", nil)
		if !sleep(400 * time.Millisecond) {
			return
		}
		publish("planning", "Plan: 2 to add, 0 to change, 0 to destroy.", nil)
	} else {
		publish("planning", fmt.Sprintf("+ %s.demo will be created", config.ResourceType), nil)
		if !sleep(400 * time.Millisecond) {
			return
		}
		publish("planning", "Plan: 1 to add, 0 to change, 0 to destroy.", nil)
	}

	if !sleep(800 * time.Millisecond) {
		return
	}

	// Phase 2: Creating
	if cancelled() {
		return
	}

	if isS3 {
		publish("creating", fmt.Sprintf("Creating S3 bucket: %s", bucketName), nil)
		if !sleep(1200 * time.Millisecond) {
			return
		}
		publish("creating", "Bucket created successfully", nil)
		if !sleep(400 * time.Millisecond) {
			return
		}

		// Phase 3: Configuring
		publish("configuring", "Applying server-side encryption (AES-256)...", nil)
		if !sleep(600 * time.Millisecond) {
			return
		}
		publish("configuring", "Encryption configuration applied", nil)
		if !sleep(300 * time.Millisecond) {
			return
		}

		publish("configuring", "Configuring bucket versioning...", nil)
		if !sleep(500 * time.Millisecond) {
			return
		}
		publish("configuring", "Versioning configured", nil)
		if !sleep(300 * time.Millisecond) {
			return
		}

		publish("configuring", "Applying resource tags...", nil)
		if !sleep(400 * time.Millisecond) {
			return
		}
		publish("configuring", "Tags applied: team, environment, cost-center, managed_by", nil)
		if !sleep(300 * time.Millisecond) {
			return
		}

		// Phase 4: Verifying
		publish("verifying", "Verifying bucket exists and is accessible...", nil)
		if !sleep(800 * time.Millisecond) {
			return
		}
		publish("verifying", "HeadBucket: 200 OK", nil)
		if !sleep(200 * time.Millisecond) {
			return
		}

		// Phase 5: Live
		publish("live", fmt.Sprintf("Bucket %s is LIVE in %s", bucketName, config.Region), nil)
		publish("live", fmt.Sprintf("ARN: arn:aws:s3:::%s", bucketName), nil)
		publish("live", "Resource will auto-terminate in 60 seconds", nil)

		// Countdown
		for i := 60; i >= 0; i-- {
			if cancelled() {
				return
			}
			if i%15 == 0 && i > 0 {
				publish("live", fmt.Sprintf("Auto-teardown in %ds...", i), map[string]interface{}{"countdown": i})
			}
			if !sleep(1 * time.Second) {
				return
			}
		}

		// Phase 6: Teardown
		publish("teardown", "Initiating resource cleanup...", nil)
		if !sleep(600 * time.Millisecond) {
			return
		}
		publish("teardown", "Deleting S3 bucket...", nil)
		if !sleep(800 * time.Millisecond) {
			return
		}
		publish("teardown", "Bucket deleted successfully", nil)
		if !sleep(300 * time.Millisecond) {
			return
		}
		publish("complete", "Deploy preview complete. All resources cleaned up.", nil)
	} else {
		// Non-S3: plan-only simulation
		publish("creating", fmt.Sprintf("Simulating %s deployment (plan-only mode)...", config.ResourceType), nil)
		if !sleep(800 * time.Millisecond) {
			return
		}

		publish("creating", fmt.Sprintf("%s.demo: Creating...", config.ResourceType), nil)
		if !sleep(700 * time.Millisecond) {
			return
		}
		publish("creating", fmt.Sprintf("%s.demo: Creation simulated", config.ResourceType), nil)
		if !sleep(300 * time.Millisecond) {
			return
		}

		publish("verifying", "Validating resource configuration...", nil)
		if !sleep(600 * time.Millisecond) {
			return
		}
		publish("verifying", "All resource validations passed", nil)
		if !sleep(400 * time.Millisecond) {
			return
		}

		publish("live", fmt.Sprintf("%s deployment plan verified", config.ResourceType), nil)
		publish("live", fmt.Sprintf("1 resource(s) would be created in %s %s", config.Provider, config.Region), nil)
		publish("live", "Plan-only mode: no real resources provisioned", nil)

		if !sleep(2 * time.Second) {
			return
		}
		publish("complete", "Deploy preview simulation complete.", nil)
	}
}

// publishToWSServer sends an event to the ws-server's publish endpoint.
// Fire-and-forget: failures are logged but do not halt the orchestration.
func (s *Server) publishToWSServer(ctx context.Context, channel, event string, data interface{}) {
	if s.wsServerURL == "" {
		return
	}

	body, err := json.Marshal(map[string]interface{}{
		"channel": channel,
		"event":   event,
		"data":    data,
	})
	if err != nil {
		s.logger.Warn("failed to marshal ws-server payload", zap.Error(err))
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", s.wsServerURL+"/api/publish", bytes.NewReader(body))
	if err != nil {
		s.logger.Warn("failed to create ws-server request", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.wsPublishKey != "" {
		req.Header.Set("X-API-Key", s.wsPublishKey)
	}

	resp, err := s.wsHTTPClient.Do(req)
	if err != nil {
		s.logger.Debug("ws-server publish failed", zap.String("channel", channel), zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		s.logger.Warn("ws-server publish rejected",
			zap.String("channel", channel),
			zap.Int("status", resp.StatusCode),
		)
	}
}
