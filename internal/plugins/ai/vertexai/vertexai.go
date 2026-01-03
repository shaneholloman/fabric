package vertexai

import (
	"context"
	"fmt"
	"strings"

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
	anthropicMessages := c.toMessages(msgs)
	if len(anthropicMessages) == 0 {
		return "", fmt.Errorf("no valid messages to send")
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
	var textParts []string
	for _, block := range response.Content {
		if block.Type == "text" && block.Text != "" {
			textParts = append(textParts, block.Text)
		}
	}

	if len(textParts) == 0 {
		return "", fmt.Errorf("no content in response")
	}

	return strings.Join(textParts, ""), nil
}

func (c *Client) SendStream(msgs []*chat.ChatCompletionMessage, opts *domain.ChatOptions, channel chan domain.StreamUpdate) error {
	if c.client == nil {
		close(channel)
		return fmt.Errorf("VertexAI client not initialized")
	}

	defer close(channel)
	ctx := context.Background()

	// Convert chat messages to Anthropic format
	anthropicMessages := c.toMessages(msgs)
	if len(anthropicMessages) == 0 {
		return fmt.Errorf("no valid messages to send")
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

		// Handle Content
		if event.Delta.Text != "" {
			channel <- domain.StreamUpdate{
				Type:    domain.StreamTypeContent,
				Content: event.Delta.Text,
			}
		}

		// Handle Usage
		if event.Message.Usage.InputTokens != 0 || event.Message.Usage.OutputTokens != 0 {
			channel <- domain.StreamUpdate{
				Type: domain.StreamTypeUsage,
				Usage: &domain.UsageMetadata{
					InputTokens:  int(event.Message.Usage.InputTokens),
					OutputTokens: int(event.Message.Usage.OutputTokens),
					TotalTokens:  int(event.Message.Usage.InputTokens + event.Message.Usage.OutputTokens),
				},
			}
		} else if event.Usage.InputTokens != 0 || event.Usage.OutputTokens != 0 {
			channel <- domain.StreamUpdate{
				Type: domain.StreamTypeUsage,
				Usage: &domain.UsageMetadata{
					InputTokens:  int(event.Usage.InputTokens),
					OutputTokens: int(event.Usage.OutputTokens),
					TotalTokens:  int(event.Usage.InputTokens + event.Usage.OutputTokens),
				},
			}
		}
	}

	return stream.Err()
}

func (c *Client) toMessages(msgs []*chat.ChatCompletionMessage) []anthropic.MessageParam {
	// Convert messages to Anthropic format with proper role handling
	// - System messages become part of the first user message
	// - Messages must alternate user/assistant
	// - Skip empty messages

	var anthropicMessages []anthropic.MessageParam
	var systemContent string

	isFirstUserMessage := true
	lastRoleWasUser := false

	for _, msg := range msgs {
		if strings.TrimSpace(msg.Content) == "" {
			continue // Skip empty messages
		}

		switch msg.Role {
		case chat.ChatMessageRoleSystem:
			// Accumulate system content to prepend to first user message
			if systemContent != "" {
				systemContent += "\\n" + msg.Content
			} else {
				systemContent = msg.Content
			}
		case chat.ChatMessageRoleUser:
			userContent := msg.Content
			if isFirstUserMessage && systemContent != "" {
				userContent = systemContent + "\\n\\n" + userContent
				isFirstUserMessage = false
			}
			if lastRoleWasUser {
				// Enforce alternation: add a minimal assistant message
				anthropicMessages = append(anthropicMessages, anthropic.NewAssistantMessage(anthropic.NewTextBlock("Okay.")))
			}
			anthropicMessages = append(anthropicMessages, anthropic.NewUserMessage(anthropic.NewTextBlock(userContent)))
			lastRoleWasUser = true
		case chat.ChatMessageRoleAssistant:
			// If first message is assistant and we have system content, prepend user message
			if isFirstUserMessage && systemContent != "" {
				anthropicMessages = append(anthropicMessages, anthropic.NewUserMessage(anthropic.NewTextBlock(systemContent)))
				lastRoleWasUser = true
				isFirstUserMessage = false
			} else if !lastRoleWasUser && len(anthropicMessages) > 0 {
				// Enforce alternation: add a minimal user message
				anthropicMessages = append(anthropicMessages, anthropic.NewUserMessage(anthropic.NewTextBlock("Hi")))
				lastRoleWasUser = true
			}
			anthropicMessages = append(anthropicMessages, anthropic.NewAssistantMessage(anthropic.NewTextBlock(msg.Content)))
			lastRoleWasUser = false
		default:
			// Other roles are ignored for Anthropic's message structure
			continue
		}
	}

	// If only system content was provided, create a user message with it
	if len(anthropicMessages) == 0 && systemContent != "" {
		anthropicMessages = append(anthropicMessages, anthropic.NewUserMessage(anthropic.NewTextBlock(systemContent)))
	}

	return anthropicMessages
}

func (c *Client) NeedsRawMode(modelName string) bool {
	return false
}
