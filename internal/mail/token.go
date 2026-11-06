package mail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

type tokenResult struct {
	Access  string
	Refresh string
	Kind    string
}

type tokenAttempt struct {
	endpoint string
	scope    string
	redirect string
	kind     string
}

func (s *Session) accessKind(ctx context.Context, kind string) (string, error) {
	if s.cred.Refresh == "" || s.cred.ClientID == "" {
		if kind == "imap" && s.cred.Password != "" {
			return "", nil
		}
		return "", ErrNoToken
	}
	var attempts []tokenAttempt
	switch kind {
	case "imap":
		attempts = []tokenAttempt{
			{"https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "", "", "imap"},
			{"https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "https://outlook.office.com/IMAP.AccessAsUser.All offline_access", "", "imap"},
			{"https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "https://outlook.office.com/.default", "", "imap"},
			{"https://login.live.com/oauth20_token.srf", "", "https://login.live.com/oauth20_desktop.srf", "imap"},
			{"https://login.live.com/oauth20_token.srf", "https://outlook.office.com/IMAP.AccessAsUser.All offline_access", "https://login.live.com/oauth20_desktop.srf", "imap"},
		}
	default:
		attempts = []tokenAttempt{
			{"https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "User.Read Mail.Read offline_access", "", "graph"},
			{"https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "https://graph.microsoft.com/Mail.Read offline_access", "", "graph"},
			{"https://login.microsoftonline.com/consumers/oauth2/v2.0/token", "https://graph.microsoft.com/.default", "", "graph"},
			{"https://login.live.com/oauth20_token.srf", "User.Read Mail.Read offline_access", "https://login.live.com/oauth20_desktop.srf", "graph"},
			{"https://login.live.com/oauth20_token.srf", "https://graph.microsoft.com/Mail.Read offline_access", "https://login.live.com/oauth20_desktop.srf", "graph"},
		}
	}
	sawNetwork, sawReject := false, false
	for _, attempt := range attempts {
		got, ok, network := s.refreshOnce(ctx, attempt.endpoint, attempt.scope, attempt.redirect)
		if !ok {
			if network {
				sawNetwork = true
			} else {
				sawReject = true
			}
			continue
		}
		if got.Refresh != "" && got.Refresh != s.cred.Refresh {
			s.cred.Refresh = got.Refresh
			s.rotated = true
		}
		outKind := attempt.kind
		scope := strings.ToLower(got.Kind)
		switch {
		case strings.Contains(scope, "graph.microsoft.com"):
			outKind = "graph"
		case strings.Contains(scope, "outlook.office"), strings.Contains(scope, "imap.accessasuser"):
			outKind = "imap"
		}
		if kind == "imap" && outKind == "graph" {
			continue
		}
		if kind == "graph" && outKind == "imap" {
			continue
		}
		return got.Access, nil
	}
	if sawNetwork && !sawReject {
		return "", ErrUnreachable
	}
	return "", ErrRejected
}

func (s *Session) refreshOnce(ctx context.Context, endpoint, scope, redirect string) (tokenResult, bool, bool) {
	form := url.Values{}
	form.Set("client_id", s.cred.ClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", s.cred.Refresh)
	if scope != "" {
		form.Set("scope", scope)
	}
	if redirect != "" {
		form.Set("redirect_uri", redirect)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResult{}, false, true
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.do(ctx, req)
	if err != nil {
		return tokenResult{}, false, true
	}
	defer resp.Body.Close()
	body, _ := readLimited(resp.Body, 1<<20)
	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) != nil || parsed.Error != "" || parsed.AccessToken == "" {
		return tokenResult{}, false, false
	}
	return tokenResult{Access: parsed.AccessToken, Refresh: parsed.RefreshToken, Kind: parsed.Scope}, true, false
}
