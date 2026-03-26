package audit

// Action domains — the namespace portion of "domain.verb" audit actions.
const (
	DomainException   = "exception"
	DomainFinding     = "finding"
	DomainPolicy      = "policy"
	DomainAgent       = "agent"
	DomainScan        = "scan"
	DomainRemediation = "remediation"
	DomainUser        = "user"
	DomainConfig      = "config"
	DomainReport      = "report"
	DomainSecret      = "secret"
	DomainDeploy      = "deploy_preview"
	DomainTerminal    = "terminal"
)

// Action verbs — the verb portion of "domain.verb" audit actions.
const (
	VerbCreate      = "create"
	VerbApprove     = "approve"
	VerbReject      = "reject"
	VerbWithdraw    = "withdraw"
	VerbRemediate   = "remediate"
	VerbSuppress    = "suppress"
	VerbReopen      = "reopen"
	VerbEnrich      = "enrich"
	VerbIngest      = "ingest"
	VerbEvaluate    = "evaluate"
	VerbUpdate      = "update"
	VerbStart       = "start"
	VerbStop        = "stop"
	VerbComplete    = "complete"
	VerbInvoke      = "invoke"
	VerbExecute     = "execute"
	VerbRollback    = "rollback"
	VerbLogin       = "login"
	VerbLogout      = "logout"
	VerbRoleChanged = "role_changed"
	VerbInvite      = "invite"
	VerbRotate      = "rotate"
	VerbGenerate    = "generate"
	VerbAbort       = "abort"
)

// Full action strings — convenience constants for handler call sites.
const (
	ActionExceptionCreate   = DomainException + "." + VerbCreate
	ActionExceptionApprove  = DomainException + "." + VerbApprove
	ActionExceptionReject   = DomainException + "." + VerbReject
	ActionExceptionWithdraw = DomainException + "." + VerbWithdraw

	ActionFindingRemediate = DomainFinding + "." + VerbRemediate
	ActionFindingSuppress  = DomainFinding + "." + VerbSuppress
	ActionFindingReopen    = DomainFinding + "." + VerbReopen
	ActionFindingEnrich    = DomainFinding + "." + VerbEnrich
	ActionFindingIngest    = DomainFinding + "." + VerbIngest

	ActionPolicyCreate   = DomainPolicy + "." + VerbCreate
	ActionPolicyUpdate   = DomainPolicy + "." + VerbUpdate
	ActionPolicyEvaluate = DomainPolicy + "." + VerbEvaluate

	ActionAgentStart  = DomainAgent + "." + VerbStart
	ActionAgentStop   = DomainAgent + "." + VerbStop
	ActionAgentInvoke = DomainAgent + "." + VerbInvoke

	ActionScanStart    = DomainScan + "." + VerbStart
	ActionScanComplete = DomainScan + "." + VerbComplete

	ActionRemediationCreate   = DomainRemediation + "." + VerbCreate
	ActionRemediationExecute  = DomainRemediation + "." + VerbExecute
	ActionRemediationRollback = DomainRemediation + "." + VerbRollback

	ActionUserLogin       = DomainUser + "." + VerbLogin
	ActionUserLogout      = DomainUser + "." + VerbLogout
	ActionUserRoleChanged = DomainUser + "." + VerbRoleChanged
	ActionUserInvite      = DomainUser + "." + VerbInvite

	ActionConfigUpdate = DomainConfig + "." + VerbUpdate

	ActionReportGenerate = DomainReport + "." + VerbGenerate

	ActionSecretRotate = DomainSecret + "." + VerbRotate

	ActionDeployStart = DomainDeploy + "." + VerbStart
	ActionDeployAbort = DomainDeploy + "." + VerbAbort

	ActionTerminalConnect = DomainTerminal + "." + "connect"
	ActionTerminalExecute = DomainTerminal + "." + VerbExecute
	ActionTerminalDenied  = DomainTerminal + "." + "denied"
)

// Result constants for audit entries.
const (
	ResultSuccess = "success"
	ResultDenied  = "denied"
	ResultError   = "error"
)
