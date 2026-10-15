package verifier

import (
	"fmt"
	"io"
)

type Verdict string

const (
	VerdictVerified   Verdict = "Verified"
	VerdictIncomplete Verdict = "Incomplete"
	VerdictTampered   Verdict = "Tampered"
)

// Exit codes of webapp-verify. ExitUsage is used by the binary for bad flags or an unreadable bundle.
const (
	ExitVerified   = 0
	ExitTampered   = 1
	ExitUsage      = 2
	ExitIncomplete = 3
)

type Severity string

const (
	SeverityTampered   Severity = "tampered"
	SeverityIncomplete Severity = "incomplete"
)

type Finding struct {
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject"`
	Message  string   `json:"message"`
}

type Report struct {
	Verdict      Verdict   `json:"verdict"`
	Fingerprint  string    `json:"fingerprint"`
	SessionID    string    `json:"sessionId"`
	ProjectID    string    `json:"projectId"`
	EventChunks  int       `json:"eventChunks"`
	VideoObjects int       `json:"videoObjects"`
	Events       int       `json:"events"`
	Findings     []Finding `json:"findings"`
}

func (r *Report) tampered(subject, format string, args ...any) {
	r.Findings = append(r.Findings, Finding{SeverityTampered, subject, fmt.Sprintf(format, args...)})
}

func (r *Report) incomplete(subject, format string, args ...any) {
	r.Findings = append(r.Findings, Finding{SeverityIncomplete, subject, fmt.Sprintf(format, args...)})
}

func (r *Report) has(severity Severity) bool {
	for _, f := range r.Findings {
		if f.Severity == severity {
			return true
		}
	}
	return false
}

func (r *Report) finalize() {
	switch {
	case r.has(SeverityTampered):
		r.Verdict = VerdictTampered
	case r.has(SeverityIncomplete):
		r.Verdict = VerdictIncomplete
	default:
		r.Verdict = VerdictVerified
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
}

func (r *Report) ExitCode() int {
	switch r.Verdict {
	case VerdictVerified:
		return ExitVerified
	case VerdictIncomplete:
		return ExitIncomplete
	default:
		return ExitTampered
	}
}

func (r *Report) WriteText(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s\n  session      %s (project %s)\n  trusted key  %s\n  checked      %d event chunks, %d video objects, %d events\n",
		r.Verdict, r.SessionID, r.ProjectID, r.Fingerprint, r.EventChunks, r.VideoObjects, r.Events)
	if err != nil {
		return err
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "  %-10s  %-12s %s\n", f.Severity, f.Subject, f.Message); err != nil {
			return err
		}
	}
	return nil
}
