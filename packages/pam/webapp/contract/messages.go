package contract

// JSON payloads of stream frames (CONTRACTS.md sections 1 and 4).

type VideoConfig struct {
	Codec     string `json:"codec"`
	Format    string `json:"format,omitempty"` // "annexb" for H.264
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Framerate int    `json:"framerate"`
	Epoch     int    `json:"epoch"`
	Shared    bool   `json:"shared,omitempty"` // live frames are the recording encoder's bytes (encoder mode "shared")
}

const (
	CodecStringH264Live = "avc1.42E01F"
	CodecStringVP9Live  = "vp09.00.10.08"
	CodecStringH264Rec  = "avc1.64001f"
)

type ViewerHello struct {
	Protocol int    `json:"protocol"`
	Client   string `json:"client"`
	Decoders struct {
		VP9  bool `json:"vp9"`
		H264 bool `json:"h264"`
	} `json:"decoders"`
	Viewport struct {
		Width            int     `json:"width"`
		Height           int     `json:"height"`
		DevicePixelRatio float64 `json:"devicePixelRatio"`
	} `json:"viewport"`
}

// ChooseLiveCodec applies the negotiation rule of section 1.6. ok is false when no codec fits (error "no_decoder").
// In shared encoder mode the agent offers only "h264".
func ChooseLiveCodec(hello ViewerHello, agentCodecs []string) (codec string, ok bool) {
	offered := map[string]bool{}
	for _, c := range agentCodecs {
		offered[c] = true
	}
	if hello.Decoders.VP9 && offered["vp9"] {
		return "vp9", true
	}
	if hello.Decoders.H264 && offered["h264"] {
		return "h264", true
	}
	return "", false
}

// Control kinds (CONTROL, gateway or backend -> viewer).
const (
	ControlSessionReady   = "session_ready"
	ControlStreamHidden   = "stream_hidden"
	ControlStreamShown    = "stream_shown"
	ControlInputState     = "input_state"
	ControlTimeLeft       = "time_left"
	ControlSessionEnding  = "session_ending"
	ControlViewerDegraded = "viewer_degraded"
	ControlRecordingState = "recording_state"
	ControlError          = "error"
)

// ControlDown is the CONTROL payload; only the fields of its kind are set.
type ControlDown struct {
	Kind          string         `json:"kind"`
	SessionID     string         `json:"sessionId,omitempty"`
	ExpiresAt     string         `json:"expiresAt,omitempty"`
	InputEnabled  *bool          `json:"inputEnabled,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	Enabled       *bool          `json:"enabled,omitempty"`
	SecondsLeft   *int           `json:"secondsLeft,omitempty"`
	Message       string         `json:"message,omitempty"`
	Active        *bool          `json:"active,omitempty"`
	DroppedFrames *int           `json:"droppedFrames,omitempty"`
	State         string         `json:"state,omitempty"`
	LostMs        *int64         `json:"lostMs,omitempty"`
	Code          string         `json:"code,omitempty"`
	Fatal         *bool          `json:"fatal,omitempty"`
	Policy        *SessionPolicy `json:"policy,omitempty"`
}

type SessionPolicy struct {
	Clipboard string `json:"clipboard"` // off | to_remote | from_remote | both
	Downloads string `json:"downloads"` // block | quarantine | allow
	Uploads   string `json:"uploads"`   // block | allow
}

// MonoFromPts maps a recording PTS onto the session monotonic clock (CONTRACTS.md 5.2, v1.1).
func MonoFromPts(ptsZeroUnixMs, sessionOpenWallTimeUnixMs, ptsUs int64) int64 {
	return (ptsZeroUnixMs-sessionOpenWallTimeUnixMs)*1000 + ptsUs
}

// Error codes carried by CONTROL error.
const (
	ErrCodeProtocol          = "protocol_error"
	ErrCodeFrameTooLarge     = "frame_too_large"
	ErrCodeNoDecoder         = "no_decoder"
	ErrCodeRunnerUnavailable = "runner_unavailable"
	ErrCodeCapacity          = "capacity_exhausted"
	ErrCodeLoginFailed       = "login_failed"
	ErrCodeTunnelFailed      = "tunnel_failed"
	ErrCodeSessionInUse      = "session_in_use"
	ErrCodeInternal          = "internal"
)

type ControlUp struct {
	Kind   string `json:"kind"` // "end_session" | "visibility"
	Hidden *bool  `json:"hidden,omitempty"`
}

// Input modifier bits.
const (
	ModShift = 1
	ModCtrl  = 2
	ModAlt   = 4
	ModMeta  = 8
)

// InputEvent is one viewer input event; T selects which fields apply (section 1.8).
type InputEvent struct {
	T       string  `json:"t"`
	Action  string  `json:"action,omitempty"`
	Code    string  `json:"code,omitempty"`
	Key     string  `json:"key,omitempty"`
	Mods    int     `json:"mods,omitempty"`
	Repeat  bool    `json:"repeat,omitempty"`
	X       int     `json:"x,omitempty"`
	Y       int     `json:"y,omitempty"`
	Buttons int     `json:"buttons,omitempty"`
	Button  int     `json:"button,omitempty"`
	DX      float64 `json:"dx,omitempty"`
	DY      float64 `json:"dy,omitempty"`
	Text    string  `json:"text,omitempty"`
	ID      string  `json:"id,omitempty"`
	Part    int     `json:"part,omitempty"`
	Total   int     `json:"total,omitempty"`
	Ts      float64 `json:"ts,omitempty"`
}

type InputBatch struct {
	Events []InputEvent `json:"events"`
}

type AgentHello struct {
	SessionID      string   `json:"sessionId"`
	RunnerToken    string   `json:"runnerToken"`
	AgentVersion   string   `json:"agentVersion"`
	ImageDigest    string   `json:"imageDigest"`
	LiveCodecs     []string `json:"liveCodecs"`
	RecordingCodec string   `json:"recordingCodec"`
	EncoderMode    string   `json:"encoderMode"` // "dual" | "shared"
	Display        struct {
		Width     int `json:"width"`
		Height    int `json:"height"`
		Framerate int `json:"framerate"`
	} `json:"display"`
}

type AgentWelcome struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Recording *struct {
		SegmentSeconds int `json:"segmentSeconds"`
	} `json:"recording,omitempty"`
}

type RecInitMeta struct {
	Codec         string `json:"codec"`
	Mime          string `json:"mime"`
	Width         int    `json:"width"`
	Height        int    `json:"height"`
	Timescale     int    `json:"timescale"`
	PtsZeroUnixMs int64  `json:"ptsZeroUnixMs"`
}

type RecSegmentMeta struct {
	SegmentIndex   int    `json:"segmentIndex"`
	StartPtsUs     int64  `json:"startPtsUs"`
	EndPtsUs       int64  `json:"endPtsUs"`
	FirstFrame     int64  `json:"firstFrame"`
	FrameCount     int    `json:"frameCount"`
	FramesCaptured int    `json:"framesCaptured"`
	FramesDropped  int    `json:"framesDropped"`
	SHA256         string `json:"sha256"`
}

type RecLoss struct {
	FromPtsUs  int64  `json:"fromPtsUs"`
	ToPtsUs    int64  `json:"toPtsUs"`
	FramesLost int    `json:"framesLost"`
	Reason     string `json:"reason"`
}

// AgentControl is the AGENT_CONTROL payload (gateway -> agent).
type AgentControl struct {
	Kind        string `json:"kind"` // live_start | keyframe | live_quality | live_pause | live_resume | input_enabled | shutdown
	Codec       string `json:"codec,omitempty"`
	BitrateKbps int    `json:"bitrateKbps,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// ExtCommand is the EXT_COMMAND payload (gateway -> extension, through the agent). Password is never logged.
type ExtCommand struct {
	Kind      string           `json:"kind"` // form_login | ping
	RequestID string           `json:"requestId"`
	Recipe    *FormLoginRecipe `json:"recipe,omitempty"`
	Username  string           `json:"username,omitempty"`
	Password  string           `json:"password,omitempty"`
}

type FormLoginRecipe struct {
	LoginURL         string `json:"loginUrl"`
	UsernameSelector string `json:"usernameSelector"`
	PasswordSelector string `json:"passwordSelector"`
	SubmitSelector   string `json:"submitSelector"`
	SuccessCheck     struct {
		Type  string `json:"type"` // url_prefix | selector_present
		Value string `json:"value"`
	} `json:"successCheck"`
	TimeoutMs int `json:"timeoutMs"`
}

// AgentEvent is the AGENT_EVENT payload (extension or native host -> gateway).
type AgentEvent struct {
	Kind           string   `json:"kind"` // ext_hello | credential_injected | login_result | focus | download | rrweb | guard_closed | watchdog_closed | nav_blocked | pong
	RequestID      string   `json:"requestId,omitempty"`
	ExtVersion     string   `json:"extVersion,omitempty"`
	ExtensionID    string   `json:"extensionId,omitempty"`
	Fields         []string `json:"fields,omitempty"`
	URL            string   `json:"url,omitempty"`
	OK             *bool    `json:"ok,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Sensitive      *bool    `json:"sensitive,omitempty"`
	Filename       string   `json:"filename,omitempty"`
	Mime           string   `json:"mime,omitempty"`
	Size           int64    `json:"size,omitempty"`
	SHA256         string   `json:"sha256,omitempty"`
	QuarantinePath string   `json:"quarantinePath,omitempty"`
	FrameURL       string   `json:"frameUrl,omitempty"`
	Events         []any    `json:"events,omitempty"`
	Target         string   `json:"target,omitempty"`
	WindowID       *int     `json:"windowId,omitempty"`
	TabID          *int     `json:"tabId,omitempty"`
	FrameID        *int     `json:"frameId,omitempty"`
	WmClass        string   `json:"wmClass,omitempty"`
	WmName         string   `json:"wmName,omitempty"`
	Error          string   `json:"error,omitempty"`
}
