package messaging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/mattermost/mattermost-server/v6/model"
	"net/http"
)

// Messenger is the interface for sending messages
type Messenger interface {
	Send(message string) error
}

// MattermostClient is an interface that defines the methods we use from model.Client4
type MattermostClient interface {
	CreatePost(post *model.Post) (*model.Post, *model.Response, error)
}

// MattermostMessenger implements the Messenger interface for Mattermost API
type MattermostMessenger struct {
	client  MattermostClient
	channel string
}

// NewMattermostMessenger creates a new MattermostMessenger
func NewMattermostMessenger(serverURL, token, channel string) *MattermostMessenger {
	client := model.NewAPIv4Client(serverURL)
	client.SetOAuthToken(token)
	return &MattermostMessenger{
		client:  client,
		channel: channel,
	}
}

// Send sends a message to Mattermost using the API
func (m *MattermostMessenger) Send(message string) error {
	post := &model.Post{
		ChannelId: m.channel,
		Message:   message,
	}
	_, resp, err := m.client.CreatePost(post)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// MattermostWebhookMessenger implements the Messenger interface for Mattermost webhooks
type MattermostWebhookMessenger struct {
	webhookURL string
}

// NewMattermostWebhookMessenger creates a new MattermostWebhookMessenger
func NewMattermostWebhookMessenger(webhookURL string) *MattermostWebhookMessenger {
	return &MattermostWebhookMessenger{
		webhookURL: webhookURL,
	}
}

// Send sends a message to Mattermost using a webhook
func (m *MattermostWebhookMessenger) Send(message string) error {
	payload := map[string]string{
		"text": message,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := http.Post(m.webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
