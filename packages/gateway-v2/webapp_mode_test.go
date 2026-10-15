package gatewayv2

import (
	"slices"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam"
)

func TestWebAppALPNMode(t *testing.T) {
	if !slices.Contains(nextProtosForGateway(false), "infisical-pam-web-app") {
		t.Fatal("infisical-pam-web-app is not offered")
	}
	cases := map[ForwardMode]pam.PAMProxyMode{
		ForwardModePAM:           pam.PAMProxyModeDefault,
		ForwardModePAMRDPBrowser: pam.PAMProxyModeRDPBrowser,
		ForwardModePAMWebApp:     pam.PAMProxyModeWebApp,
	}
	for mode, want := range cases {
		if got := pamProxyModeFor(mode); got != want {
			t.Fatalf("%s: got %v want %v", mode, got, want)
		}
	}
}
