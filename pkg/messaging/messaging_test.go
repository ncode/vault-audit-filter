package messaging

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClient is a mock for the SlackClient interface
type MockClient struct {
	mock.Mock
}

func (m *MockClient) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	args := m.Called(channelID)
	return "", "", args.Error(0)
}

func TestNewSlackMessenger(t *testing.T) {
	serverURL := "https://slack.example.com"
	token := "test-token"
	channel := "test-channel"

	messenger := NewSlackMessenger(serverURL, token, channel, 0)

	assert.NotNil(t, messenger, "NewSlackMessenger should return a non-nil messenger")
	assert.Equal(t, channel, messenger.channel, "Channel should be set correctly")

	_, ok := messenger.client.(*slack.Client)
	assert.True(t, ok, "Client should be of type *slack.Client")

	emptyMessenger := NewSlackMessenger("", "", "", 0)
	assert.NotNil(t, emptyMessenger, "NewSlackMessenger should return a non-nil messenger even with empty inputs")
	assert.Empty(t, emptyMessenger.channel, "Channel should be empty")
}

func TestSlackMessenger_Send(t *testing.T) {
	mockClient := new(MockClient)
	messenger := &SlackMessenger{
		client:  mockClient,
		channel: "test-channel",
	}

	testMessage := "Test message"

	t.Run("Successful send", func(t *testing.T) {
		mockClient.On("PostMessage", "test-channel").Return(nil).Once()
		err := messenger.Send(testMessage)
		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
	})

	t.Run("API error", func(t *testing.T) {
		mockClient.On("PostMessage", "test-channel").Return(fmt.Errorf("API error")).Once()
		err := messenger.Send(testMessage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to send message")
		mockClient.AssertExpectations(t)
	})
}

func TestSlackWebhookMessenger_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	messenger := NewSlackWebhookMessenger(server.URL, 0)
	err := messenger.Send("Test message")
	assert.NoError(t, err)
}

func TestSlackWebhookMessenger_SendError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	messenger := NewSlackWebhookMessenger(server.URL, 0)
	err := messenger.Send("Test message")
	assert.Error(t, err)
}

func TestNewSlackWebhookMessenger(t *testing.T) {
	webhookURL := "https://slack.example.com/hooks/abc123"
	messenger := NewSlackWebhookMessenger(webhookURL, 0)

	assert.NotNil(t, messenger, "NewSlackWebhookMessenger should return a non-nil messenger")
	assert.Equal(t, webhookURL, messenger.webhookURL, "Webhook URL should be set correctly")

	emptyMessenger := NewSlackWebhookMessenger("", 0)
	assert.NotNil(t, emptyMessenger, "NewSlackWebhookMessenger should return a non-nil messenger even with empty webhook URL")
	assert.Empty(t, emptyMessenger.webhookURL, "Webhook URL should be empty")
}

func TestSlackWebhookMessenger_SendInvalidURL(t *testing.T) {
	messenger := NewSlackWebhookMessenger("http://[::1]:NamedPort", 0)
	err := messenger.Send("Test message")
	assert.Error(t, err)
}

func TestSlackWebhookMessenger_SendEmptyURL(t *testing.T) {
	messenger := NewSlackWebhookMessenger("", 0)
	err := messenger.Send("Test message")
	assert.Error(t, err)
}

func TestSlackWebhookMessenger_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewSlackWebhookMessenger(srv.URL, 10*time.Millisecond)
	err := m.Send("msg")
	assert.Error(t, err)
}

func TestSlackMessenger_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	m := NewSlackMessenger(srv.URL, "token", "chan", 10*time.Millisecond)
	err := m.Send("msg")
	assert.Error(t, err)
}
