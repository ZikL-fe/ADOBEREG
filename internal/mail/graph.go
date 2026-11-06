package mail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Session) listGraph(ctx context.Context, access string) ([]Item, error) {
	var all []Item
	seen := map[string]struct{}{}
	for _, folder := range []string{"inbox", "junkemail"} {
		items, err := s.graphListFolder(ctx, access, folder, true)
		if err == errGraphOrder {
			items, err = s.graphListFolder(ctx, access, folder, false)
		}
		if err != nil {
			if folder == "inbox" {
				return nil, err
			}
			continue
		}
		for _, item := range items {
			if _, ok := seen[item.ID]; ok {
				continue
			}
			seen[item.ID] = struct{}{}
			all = append(all, item)
		}
	}
	sortItemsNewestFirst(all)
	if len(all) > 40 {
		all = all[:40]
	}
	return all, nil
}

var errGraphOrder = errString("graph order")

type errString string

func (e errString) Error() string { return string(e) }

func (s *Session) graphListFolder(ctx context.Context, access, folder string, order bool) ([]Item, error) {
	query := url.Values{}
	query.Set("$top", "20")
	query.Set("$select", "id,subject,from,receivedDateTime,bodyPreview,isRead")
	if order {
		query.Set("$orderby", "receivedDateTime desc")
	}
	endpoints := []string{
		"https://graph.microsoft.com/v1.0/me/mailFolders/" + url.PathEscape(folder) + "/messages?" + query.Encode(),
		"https://graph.microsoft.com/v1.0/users/" + url.PathEscape(s.Email) + "/mailFolders/" + url.PathEscape(folder) + "/messages?" + query.Encode(),
	}
	var last error
	for _, endpoint := range endpoints {
		items, err := s.graphListURL(ctx, access, endpoint, order)
		if err == nil {
			return items, nil
		}
		if err == errGraphOrder {
			return nil, err
		}
		last = err
	}
	if last == nil {
		last = ErrUnreachable
	}
	return nil, last
}

func (s *Session) graphListURL(ctx context.Context, access, endpoint string, order bool) ([]Item, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, ErrUnreachable
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := s.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := readLimited(resp.Body, 2<<20)
	if resp.StatusCode == http.StatusBadRequest && order {
		return nil, errGraphOrder
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrRejected
	}
	if resp.StatusCode >= 400 {
		return nil, ErrUnreachable
	}
	var parsed struct {
		Value []struct {
			ID               string `json:"id"`
			Subject          string `json:"subject"`
			BodyPreview      string `json:"bodyPreview"`
			ReceivedDateTime string `json:"receivedDateTime"`
			IsRead           bool   `json:"isRead"`
			From             struct {
				Email struct {
					Name    string `json:"name"`
					Address string `json:"address"`
				} `json:"emailAddress"`
			} `json:"from"`
		} `json:"value"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return nil, ErrUnreachable
	}
	items := make([]Item, 0, len(parsed.Value))
	for _, row := range parsed.Value {
		if row.ID == "" {
			continue
		}
		from := row.From.Email.Name
		if from == "" {
			from = row.From.Email.Address
		} else if row.From.Email.Address != "" {
			from = from + " <" + row.From.Email.Address + ">"
		}
		when, _ := time.Parse(time.RFC3339, row.ReceivedDateTime)
		items = append(items, Item{
			ID: "graph:" + row.ID, Subject: row.Subject, From: from,
			ReceivedAt: when.UTC(), Preview: row.BodyPreview, Unread: !row.IsRead,
		})
	}
	return items, nil
}

func (s *Session) getGraph(ctx context.Context, access, id string) (Detail, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Detail{}, ErrNotFound
	}
	query := url.Values{}
	query.Set("$select", "subject,from,receivedDateTime,body")
	endpoints := []string{
		"https://graph.microsoft.com/v1.0/me/messages/" + url.PathEscape(id) + "?" + query.Encode(),
		"https://graph.microsoft.com/v1.0/users/" + url.PathEscape(s.Email) + "/messages/" + url.PathEscape(id) + "?" + query.Encode(),
	}
	var last error
	for _, endpoint := range endpoints {
		detail, err := s.getGraphURL(ctx, access, endpoint)
		if err == nil {
			return detail, nil
		}
		last = err
	}
	if last == nil {
		last = ErrUnreachable
	}
	return Detail{}, last
}

func (s *Session) getGraphURL(ctx context.Context, access, endpoint string) (Detail, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Detail{}, ErrUnreachable
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := s.do(ctx, req)
	if err != nil {
		return Detail{}, err
	}
	defer resp.Body.Close()
	body, _ := readLimited(resp.Body, 1<<20)
	if resp.StatusCode == http.StatusNotFound {
		return Detail{}, ErrNotFound
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return Detail{}, ErrRejected
	}
	if resp.StatusCode >= 400 {
		return Detail{}, ErrUnreachable
	}
	var parsed struct {
		Subject          string `json:"subject"`
		ReceivedDateTime string `json:"receivedDateTime"`
		From             struct {
			Email struct {
				Name    string `json:"name"`
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"from"`
		Body struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return Detail{}, ErrUnreachable
	}
	from := parsed.From.Email.Name
	if from == "" {
		from = parsed.From.Email.Address
	} else if parsed.From.Email.Address != "" {
		from = from + " <" + parsed.From.Email.Address + ">"
	}
	when, _ := time.Parse(time.RFC3339, parsed.ReceivedDateTime)
	kind := "text"
	if strings.Contains(strings.ToLower(parsed.Body.ContentType), "html") {
		kind = "html"
	}
	content := parsed.Body.Content
	if len(content) > 512<<10 {
		content = content[:512<<10]
	}
	return Detail{Subject: parsed.Subject, From: from, ReceivedAt: when.UTC(), ContentType: kind, Body: content}, nil
}
