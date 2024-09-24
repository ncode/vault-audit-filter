package messaging

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mattermost/mattermost-server/v6/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClient is a mock for the MattermostClient interface
type MockClient struct {
	mock.Mock
}

func (m *MockClient) CreatePost(post *model.Post) (*model.Post, *model.Response, error) {
	args := m.Called(post)
	return args.Get(0).(*model.Post), args.Get(1).(*model.Response), args.Error(2)
}

func TestMattermostMessenger_Send(t *testing.T) {
	mockClient := new(MockClient)
	messenger := &MattermostMessenger{
		client:  mockClient,
		channel: "test-channel",
	}

	testMessage := "Test message"
	expectedPost := &model.Post{
		ChannelId: "test-channel",
		Message:   testMessage,
	}

	t.Run("Successful send", func(t *testing.T) {
		mockClient.On("CreatePost", expectedPost).Return(&model.Post{}, &model.Response{StatusCode: http.StatusCreated}, nil).Once()
		err := messenger.Send(testMessage)
		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
	})

	t.Run("API error", func(t *testing.T) {
		mockClient.On("CreatePost", expectedPost).Return((*model.Post)(nil), &model.Response{StatusCode: http.StatusBadRequest}, fmt.Errorf("API error")).Once()
		err := messenger.Send(testMessage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to send message: API error")
		mockClient.AssertExpectations(t)
	})

	t.Run("Unexpected status code", func(t *testing.T) {
		mockClient.On("CreatePost", expectedPost).Return(&model.Post{}, &model.Response{StatusCode: http.StatusOK}, nil).Once()
		err := messenger.Send(testMessage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected status code: 200")
		mockClient.AssertExpectations(t)
	})
}

func TestMattermostWebhookMessenger_Send(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	messenger := NewMattermostWebhookMessenger(server.URL)

	// Test the Send method
	err := messenger.Send("Test message")

	// Assert
	assert.NoError(t, err)
}

func TestMattermostWebhookMessenger_SendError(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	messenger := NewMattermostWebhookMessenger(server.URL)

	// Test the Send method
	err := messenger.Send("Test message")

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code: 500")
}
