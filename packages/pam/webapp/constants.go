package webapp

import "time"

// Session end reasons, recorded in session_end and sent in session_ending (CONTRACTS.md).
const (
	endError           = "error"
	endRunnerExit      = "runner_exit"
	endUserEnd         = "user_end"
	endExpired         = "expired"
	endAdminTerminated = "admin_terminated"
	endViewerLost      = "viewer_lost"
	endRecordingFailed = "recording_failed"
	endIdle            = "idle"
	endGatewayShutdown = "gateway_shutdown"
)

// AGENT_CONTROL kinds (gateway -> agent).
const (
	agentLiveStart  = "live_start"
	agentKeyframe   = "keyframe"
	agentLivePause  = "live_pause"
	agentLiveResume = "live_resume"
	agentShutdown   = "shutdown"
)

// CONTROL_UP kinds (viewer -> gateway).
const (
	controlUpEndSession = "end_session"
	controlUpVisibility = "visibility"
)

const (
	codecVP9  = "vp9"
	codecH264 = "h264"

	encoderModeDual = "dual"

	overflowTerminate        = "terminate"
	overflowContinueWithLoss = "continue_with_loss"

	recordingStateLoss = "loss"

	lossReasonSegmentRejected = "segment_rejected"
	continuityAgentLost       = "agent_disconnected"
)

const (
	sessionKeyBytes = 32
	liveBitrateKbps = 2500

	linkWriteTimeout     = 10 * time.Second
	viewerEnqueueWait    = 5 * time.Second
	viewerFlushWait      = 2 * time.Second
	viewerErrorFlushWait = time.Second

	healthProbeTimeout   = 5 * time.Second
	agentHelloTimeout    = 15 * time.Second
	runnerIPWait         = 10 * time.Second
	readyGraceExtra      = 5 * time.Second
	launchTimeout        = 90 * time.Second
	destroyTimeout       = 30 * time.Second
	recorderCloseTimeout = 60 * time.Second
)
