package vertexai

import (
	"context"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/vertex"
	"github.com/danielmiessler/fabric/internal/chat"
	"github.com/danielmiessler/fabric/internal/domain"
	"github.com/danielmiessler/fabric/internal/plugins"
)

const (
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	defaultRegion      = "global"
	maxTokens          = 4096
)

// NewClient creates a new Vertex AI client for accessing Claude models via Google Cloud
func NewClient() (ret *Client) {
	vendorName := "VertexAI"
	ret = &Client{}

	ret.PluginBase = &plugins.PluginBase{
		Name:            vendorName,
		EnvNamePrefix:   plugins.BuildEnvVariablePrefix(vendorName),
		ConfigureCustom: ret.configure,
	}

	ret.ProjectID = ret.AddSetupQuestion("Project ID", true)
	ret.Region = ret.AddSetupQuestion("Region", false)
	ret.Region.Value = defaultRegion

	return
}

// Client implements the ai.Vendor interface for Google Cloud Vertex AI with Anthropic models
type Client struct {
	*plugins.PluginBase
	ProjectID *plugins.SetupQuestion
	Region    *plugins.SetupQuestion

	client *anthropic.Client
}

func (c *Client) configure() error {
	ctx := context.Background()
	projectID := c.ProjectID.Value
	region := c.Region.Value

	// Initialize Anthropic client for Claude models via Vertex AI using Google ADC
	vertexOpt := vertex.WithGoogleAuth(ctx, region, projectID, cloudPlatformScope)
	client := anthropic.NewClient(vertexOpt)
	c.client = &client

	return nil
}

func (c *Client) ListModels() ([]string, error) {
	// Return Claude models available on Vertex AI
	return []string{
		string(anthropic.ModelClaudeSonnet4_5),
		string(anthropic.ModelClaudeOpus4_5),
		string(anthropic.ModelClaudeHaiku4_5),
		string(anthropic.ModelClaude3_7SonnetLatest),
		string(anthropic.ModelClaude3_5HaikuLatest),
	}, nil
}

func (c *Client) Send(ctx context.Context, msgs []*chat.ChatCompletionMessage, opts *domain.ChatOptions) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("VertexAI client not initialized")
	}

	// Convert chat messages to Anthropic format
	anthropicMessages := make([]anthropic.MessageParam, len(msgs))
	for i, msg := range msgs {
		anthropicMessages[i] = anthropic.NewUserMessage(anthropic.NewTextBlock(msg.Content))
	}

	// Create the request
	response, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:       anthropic.Model(opts.Model),
		MaxTokens:   int64(maxTokens),
		Messages:    anthropicMessages,
		Temperature: anthropic.Opt(opts.Temperature),
	})

	if err != nil {
		return "", err
	}

	// Extract text from response
	if len(response.Content) > 0 {
		return response.Content[0].Text, nil
	}

	return "", fmt.Errorf("no content in response")
}

func (c *Client) SendStream(msgs []*chat.ChatCompletionMessage, opts *domain.ChatOptions, channel chan string) error {
	if c.client == nil {
		close(channel)
		return fmt.Errorf("VertexAI client not initialized")
	}

	defer close(channel)
	ctx := context.Background()

	// Convert chat messages to Anthropic format
	anthropicMessages := make([]anthropic.MessageParam, len(msgs))
	for i, msg := range msgs {
		anthropicMessages[i] = anthropic.NewUserMessage(anthropic.NewTextBlock(msg.Content))
	}

	// Create streaming request
	stream := c.client.Messages.NewStreaming(ctx, anthropic.MessageNewParams{
		Model:       anthropic.Model(opts.Model),
		MaxTokens:   int64(maxTokens),
		Messages:    anthropicMessages,
		Temperature: anthropic.Opt(opts.Temperature),
	})

	// Process stream
	for stream.Next() {
		event := stream.Current()
		if event.Delta.Text != "" {
			channel <- event.Delta.Text
		}
	}

	return stream.Err()
}

func (c *Client) NeedsRawMode(modelName string) bool {
	return false
}
