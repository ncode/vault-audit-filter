package messaging

import (
	"fmt"
	"github.com/slack-go/slack"
)

// Messenger is the interface for sending messages
type Messenger interface {
	Send(message string) error
}

// SlackClient defines the Slack API methods we use
type SlackClient interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
}

// SlackMessenger implements the Messenger interface for the Slack API
type SlackMessenger struct {
	client  SlackClient
	channel string
}

// NewSlackMessenger creates a new SlackMessenger
func NewSlackMessenger(serverURL, token, channel string) *SlackMessenger {
	opts := []slack.Option{}
	if serverURL != "" {
		opts = append(opts, slack.OptionAPIURL(serverURL))
	}
	client := slack.New(token, opts...)
	return &SlackMessenger{client: client, channel: channel}
}

// Send sends a message to Slack using the API
func (m *SlackMessenger) Send(message string) error {
	_, _, err := m.client.PostMessage(m.channel, slack.MsgOptionText(message, false))
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	return nil
}

// SlackWebhookMessenger implements the Messenger interface for Slack webhooks
type SlackWebhookMessenger struct {
	webhookURL string
}

// NewSlackWebhookMessenger creates a new SlackWebhookMessenger
func NewSlackWebhookMessenger(webhookURL string) *SlackWebhookMessenger {
	return &SlackWebhookMessenger{webhookURL: webhookURL}
}

// Send sends a message to Slack using a webhook
func (m *SlackWebhookMessenger) Send(message string) error {
	err := slack.PostWebhook(m.webhookURL, &slack.WebhookMessage{Text: message})
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	return nil
}
