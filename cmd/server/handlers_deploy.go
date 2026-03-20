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

// deployPreviewRun holds the state for a single deploy preview execution.
// Extracted from runDeployPreview to decompose the 188-line function into phases.
type deployPreviewRun struct {
	server     *Server
	ctx        context.Context
	config     DeployPreviewConfig
	channel    string
	bucketName string
}

func (r *deployPreviewRun) publish(event, message string, extra map[string]interface{}) {
	data := map[string]interface{}{"message": message}
	for k, v := range extra {
		data[k] = v
	}
	r.server.publishToWSServer(r.ctx, r.channel, event, data)
}

func (r *deployPreviewRun) cancelled() bool {
	return r.ctx.Err() != nil
}

func (r *deployPreviewRun) sleep(d time.Duration) bool {
	select {
	case <-r.ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// runDeployPreview orchestrates the deploy preview, publishing SSE events to ws-server.
func (s *Server) runDeployPreview(ctx context.Context, execID string, config DeployPreviewConfig) {
	defer s.deployTracker.remove(execID)

	r := &deployPreviewRun{
		server:     s,
		ctx:        ctx,
		config:     config,
		channel:    "deploy:" + execID,
		bucketName: fmt.Sprintf("cf-demo-%s-%d", config.AppID, time.Now().UnixMilli()),
	}

	if !r.planResources() {
		return
	}

	if config.ResourceType == "s3" {
		r.executeS3Deploy()
	} else {
		r.executeGenericDeploy()
	}
}

// planResources emits Terraform init messages and the resource plan.
// Returns false if the context was cancelled during planning.
func (r *deployPreviewRun) planResources() bool {
	r.publish("planning", "Initializing Terraform provider...", nil)
	if !r.sleep(800 * time.Millisecond) {
		return false
	}

	r.publish("planning", fmt.Sprintf("Provider: %s | Region: %s", r.config.Provider, r.config.Region), nil)
	if !r.sleep(500 * time.Millisecond) {
		return false
	}

	r.publish("planning", "Terraform v1.9.8 | Format 1.2", nil)
	if !r.sleep(600 * time.Millisecond) {
		return false
	}

	if r.config.ResourceType == "s3" {
		r.publish("planning", "+ aws_s3_bucket.demo will be created", nil)
		if !r.sleep(400 * time.Millisecond) {
			return false
		}
		r.publish("planning", "+ aws_s3_bucket_server_side_encryption_configuration.demo will be created", nil)
		if !r.sleep(400 * time.Millisecond) {
			return false
		}
		r.publish("planning", "Plan: 2 to add, 0 to change, 0 to destroy.", nil)
	} else {
		r.publish("planning", fmt.Sprintf("+ %s.demo will be created", r.config.ResourceType), nil)
		if !r.sleep(400 * time.Millisecond) {
			return false
		}
		r.publish("planning", "Plan: 1 to add, 0 to change, 0 to destroy.", nil)
	}

	return r.sleep(800 * time.Millisecond)
}

// executeS3Deploy runs the S3-specific create, configure, verify, live, and teardown phases.
func (r *deployPreviewRun) executeS3Deploy() {
	if r.cancelled() {
		return
	}
	if !r.createS3Bucket() {
		return
	}
	if !r.configureS3Bucket() {
		return
	}
	if !r.verifyS3Bucket() {
		return
	}
	if !r.runS3LiveCountdown() {
		return
	}
	r.teardownS3Bucket()
}

// createS3Bucket emits bucket creation messages.
func (r *deployPreviewRun) createS3Bucket() bool {
	r.publish("creating", fmt.Sprintf("Creating S3 bucket: %s", r.bucketName), nil)
	if !r.sleep(1200 * time.Millisecond) {
		return false
	}
	r.publish("creating", "Bucket created successfully", nil)
	return r.sleep(400 * time.Millisecond)
}

// configureS3Bucket emits encryption, versioning, and tagging configuration messages.
func (r *deployPreviewRun) configureS3Bucket() bool {
	r.publish("configuring", "Applying server-side encryption (AES-256)...", nil)
	if !r.sleep(600 * time.Millisecond) {
		return false
	}
	r.publish("configuring", "Encryption configuration applied", nil)
	if !r.sleep(300 * time.Millisecond) {
		return false
	}

	r.publish("configuring", "Configuring bucket versioning...", nil)
	if !r.sleep(500 * time.Millisecond) {
		return false
	}
	r.publish("configuring", "Versioning configured", nil)
	if !r.sleep(300 * time.Millisecond) {
		return false
	}

	r.publish("configuring", "Applying resource tags...", nil)
	if !r.sleep(400 * time.Millisecond) {
		return false
	}
	r.publish("configuring", "Tags applied: team, environment, cost-center, managed_by", nil)
	return r.sleep(300 * time.Millisecond)
}

// verifyS3Bucket emits the bucket accessibility check messages.
func (r *deployPreviewRun) verifyS3Bucket() bool {
	r.publish("verifying", "Verifying bucket exists and is accessible...", nil)
	if !r.sleep(800 * time.Millisecond) {
		return false
	}
	r.publish("verifying", "HeadBucket: 200 OK", nil)
	return r.sleep(200 * time.Millisecond)
}

// runS3LiveCountdown emits the live status and runs the 60-second countdown.
func (r *deployPreviewRun) runS3LiveCountdown() bool {
	r.publish("live", fmt.Sprintf("Bucket %s is LIVE in %s", r.bucketName, r.config.Region), nil)
	r.publish("live", fmt.Sprintf("ARN: arn:aws:s3:::%s", r.bucketName), nil)
	r.publish("live", "Resource will auto-terminate in 60 seconds", nil)

	for i := 60; i >= 0; i-- {
		if r.cancelled() {
			return false
		}
		if i%15 == 0 && i > 0 {
			r.publish("live", fmt.Sprintf("Auto-teardown in %ds...", i), map[string]interface{}{"countdown": i})
		}
		if !r.sleep(1 * time.Second) {
			return false
		}
	}
	return true
}

// teardownS3Bucket emits resource cleanup messages.
func (r *deployPreviewRun) teardownS3Bucket() {
	r.publish("teardown", "Initiating resource cleanup...", nil)
	if !r.sleep(600 * time.Millisecond) {
		return
	}
	r.publish("teardown", "Deleting S3 bucket...", nil)
	if !r.sleep(800 * time.Millisecond) {
		return
	}
	r.publish("teardown", "Bucket deleted successfully", nil)
	if !r.sleep(300 * time.Millisecond) {
		return
	}
	r.publish("complete", "Deploy preview complete. All resources cleaned up.", nil)
}

// executeGenericDeploy runs the non-S3 plan-only simulation path.
func (r *deployPreviewRun) executeGenericDeploy() {
	r.publish("creating", fmt.Sprintf("Simulating %s deployment (plan-only mode)...", r.config.ResourceType), nil)
	if !r.sleep(800 * time.Millisecond) {
		return
	}

	r.publish("creating", fmt.Sprintf("%s.demo: Creating...", r.config.ResourceType), nil)
	if !r.sleep(700 * time.Millisecond) {
		return
	}
	r.publish("creating", fmt.Sprintf("%s.demo: Creation simulated", r.config.ResourceType), nil)
	if !r.sleep(300 * time.Millisecond) {
		return
	}

	r.publish("verifying", "Validating resource configuration...", nil)
	if !r.sleep(600 * time.Millisecond) {
		return
	}
	r.publish("verifying", "All resource validations passed", nil)
	if !r.sleep(400 * time.Millisecond) {
		return
	}

	r.publish("live", fmt.Sprintf("%s deployment plan verified", r.config.ResourceType), nil)
	r.publish("live", fmt.Sprintf("1 resource(s) would be created in %s %s", r.config.Provider, r.config.Region), nil)
	r.publish("live", "Plan-only mode: no real resources provisioned", nil)

	if !r.sleep(2 * time.Second) {
		return
	}
	r.publish("complete", "Deploy preview simulation complete.", nil)
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
