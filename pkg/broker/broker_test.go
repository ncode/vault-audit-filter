package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	serverAddr = "localhost:6380"
)

var (
	testServer *Server
	certFile   string
	keyFile    string
)

func generateTempCert() (string, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	certFile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		return "", "", err
	}
	keyFile, err := os.CreateTemp("", "key*.pem")
	if err != nil {
		return "", "", err
	}

	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certFile.Name(), keyFile.Name(), nil
}

func TestMain(m *testing.M) {
	var err error
	certFile, keyFile, err = generateTempCert()
	if err != nil {
		fmt.Printf("Failed to generate temporary certificates: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	testServer, err = NewServer(serverAddr, logger, certFile, keyFile)
	if err != nil {
		fmt.Printf("Failed to create server: %v\n", err)
		os.Exit(1)
	}

	go func() {
		if err := testServer.ListenAndServeTLS(); err != nil {
			fmt.Printf("Failed to start server: %v\n", err)
			os.Exit(1)
		}
	}()

	// Wait for the server to start
	time.Sleep(time.Second)

	// Run tests
	code := m.Run()

	// Exit
	os.Exit(code)
}

func newTLSClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr: serverAddr,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // Only for testing. In production, use proper certificate verification.
		},
	})
}

func TestPubSub(t *testing.T) {
	tests := []struct {
		name                   string
		channel                string
		message                string
		expectedSubs           int64
		unsubscribe            bool
		publishAgain           bool
		expectedSubsAfterUnsub int64
	}{
		{
			name:         "Single subscriber",
			channel:      "test-channel-1",
			message:      "Hello, World!",
			expectedSubs: 1,
			unsubscribe:  false,
			publishAgain: false,
		},
		{
			name:                   "Unsubscribe",
			channel:                "test-channel-2",
			message:                "Hello, World!",
			expectedSubs:           1,
			unsubscribe:            true,
			publishAgain:           true,
			expectedSubsAfterUnsub: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			publisher := newTLSClient()
			subscriber := newTLSClient()
			defer publisher.Close()
			defer subscriber.Close()

			pubsub := subscriber.Subscribe(ctx, tt.channel)
			defer pubsub.Close()

			_, err := pubsub.Receive(ctx)
			assert.NoError(t, err)

			msg, err := publisher.Publish(ctx, tt.channel, tt.message).Result()
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedSubs, msg)

			message, err := pubsub.ReceiveMessage(ctx)
			assert.NoError(t, err)
			assert.Equal(t, tt.message, message.Payload)
			assert.Equal(t, tt.channel, message.Channel)

			if tt.unsubscribe {
				err = pubsub.Unsubscribe(ctx, tt.channel)
				assert.NoError(t, err)
				time.Sleep(100 * time.Millisecond)
			}

			if tt.publishAgain {
				msg, err = publisher.Publish(ctx, tt.channel, "Hello again!").Result()
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSubsAfterUnsub, msg)
			}
		})
	}
}

func TestMultipleSubscribers(t *testing.T) {
	ctx := context.Background()
	publisher := newTLSClient()
	subscriber1 := newTLSClient()
	subscriber2 := newTLSClient()
	defer publisher.Close()
	defer subscriber1.Close()
	defer subscriber2.Close()

	pubsub1 := subscriber1.Subscribe(ctx, "test-channel")
	pubsub2 := subscriber2.Subscribe(ctx, "test-channel")
	defer pubsub1.Close()
	defer pubsub2.Close()

	// Wait for subscriptions to be established
	_, err := pubsub1.Receive(ctx)
	assert.NoError(t, err)
	_, err = pubsub2.Receive(ctx)
	assert.NoError(t, err)

	msg, err := publisher.Publish(ctx, "test-channel", "Hello, everyone!").Result()
	assert.NoError(t, err)
	assert.Equal(t, int64(2), msg) // Expecting 2 subscribers

	message1, err := pubsub1.ReceiveMessage(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, everyone!", message1.Payload)

	message2, err := pubsub2.ReceiveMessage(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, everyone!", message2.Payload)
}

func TestPSubscribe(t *testing.T) {
	ctx := context.Background()
	publisher := newTLSClient()
	subscriber := newTLSClient()
	defer publisher.Close()
	defer subscriber.Close()

	pubsub := subscriber.PSubscribe(ctx, "test-*")
	defer pubsub.Close()

	_, err := pubsub.Receive(ctx)
	assert.NoError(t, err)

	msg, err := publisher.Publish(ctx, "test-channel", "Hello, pattern!").Result()
	assert.NoError(t, err)
	assert.Equal(t, int64(1), msg)

	message, err := pubsub.ReceiveMessage(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, pattern!", message.Payload)
	assert.Equal(t, "test-channel", message.Channel)
}
