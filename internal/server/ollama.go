package restapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielmiessler/fabric/internal/core"
	"github.com/gin-gonic/gin"
)

type OllamaModel struct {
	Models []Model `json:"models"`
}
type Model struct {
	Details    ModelDetails `json:"details"`
	Digest     string       `json:"digest"`
	Model      string       `json:"model"`
	ModifiedAt string       `json:"modified_at"`
	Name       string       `json:"name"`
	Size       int64        `json:"size"`
}

type ModelDetails struct {
	Families          []string `json:"families"`
	Family            string   `json:"family"`
	Format            string   `json:"format"`
	ParameterSize     string   `json:"parameter_size"`
	ParentModel       string   `json:"parent_model"`
	QuantizationLevel string   `json:"quantization_level"`
}

type APIConvert struct {
	registry *core.PluginRegistry
	r        *gin.Engine
	addr     *string
}

type OllamaRequestBody struct {
	Messages []OllamaMessage `json:"messages"`
	Model    string          `json:"model"`
	Options  struct {
	} `json:"options"`
	Stream bool `json:"stream"`
}

type OllamaMessage struct {
	Content string `json:"content"`
	Role    string `json:"role"`
}

type OllamaResponse struct {
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
	Message   struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	DoneReason         string `json:"done_reason,omitempty"`
	Done               bool   `json:"done"`
	TotalDuration      int64  `json:"total_duration,omitempty"`
	LoadDuration       int64  `json:"load_duration,omitempty"`
	PromptEvalCount    int    `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64  `json:"prompt_eval_duration,omitempty"`
	EvalCount          int    `json:"eval_count,omitempty"`
	EvalDuration       int64  `json:"eval_duration,omitempty"`
}

type FabricResponseFormat struct {
	Type    string `json:"type"`
	Format  string `json:"format"`
	Content string `json:"content"`
}

func ServeOllama(registry *core.PluginRegistry, address string, version string) (err error) {
	r := gin.New()

	// Middleware
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Register routes
	fabricDb := registry.Db
	NewPatternsHandler(r, fabricDb.Patterns)
	NewContextsHandler(r, fabricDb.Contexts)
	NewSessionsHandler(r, fabricDb.Sessions)
	NewChatHandler(r, registry, fabricDb)
	NewConfigHandler(r, fabricDb)
	NewModelsHandler(r, registry.VendorManager)

	typeConversion := APIConvert{
		registry: registry,
		r:        r,
		addr:     &address,
	}
	// Ollama Endpoints
	r.GET("/api/tags", typeConversion.ollamaTags)
	r.GET("/api/version", func(c *gin.Context) {
		c.Data(200, "application/json", fmt.Appendf(nil, "{\"%s\"}", version))
	})
	r.POST("/api/chat", typeConversion.ollamaChat)

	// Start server
	err = r.Run(address)
	if err != nil {
		return err
	}

	return
}

func (f APIConvert) ollamaTags(c *gin.Context) {
	patterns, err := f.registry.Db.Patterns.GetNames()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	var response OllamaModel
	for _, pattern := range patterns {
		today := time.Now().Format("2024-11-25T12:07:58.915991813-05:00")
		details := ModelDetails{
			Families:          []string{"fabric"},
			Family:            "fabric",
			Format:            "custom",
			ParameterSize:     "42.0B",
			ParentModel:       "",
			QuantizationLevel: "",
		}
		response.Models = append(response.Models, Model{
			Details:    details,
			Digest:     "365c0bd3c000a25d28ddbf732fe1c6add414de7275464c4e4d1c3b5fcb5d8ad1",
			Model:      fmt.Sprintf("%s:latest", pattern),
			ModifiedAt: today,
			Name:       fmt.Sprintf("%s:latest", pattern),
			Size:       0,
		})
	}

	c.JSON(200, response)

}

func (f APIConvert) ollamaChat(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "testing endpoint"})
		return
	}
	var prompt OllamaRequestBody
	err = json.Unmarshal(body, &prompt)
	if err != nil {
		log.Printf("Error unmarshalling body: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "testing endpoint"})
		return
	}
	now := time.Now()
	var chat ChatRequest

	if len(prompt.Messages) == 1 {
		chat.Prompts = []PromptRequest{{
			UserInput:   prompt.Messages[0].Content,
			Vendor:      "",
			Model:       "",
			ContextName: "",
			PatternName: strings.Split(prompt.Model, ":")[0],
		}}
	} else if len(prompt.Messages) > 1 {
		var content string
		for _, msg := range prompt.Messages {
			content = fmt.Sprintf("%s%s:%s\n", content, msg.Role, msg.Content)
		}
		chat.Prompts = []PromptRequest{{
			UserInput:   content,
			Vendor:      "",
			Model:       "",
			ContextName: "",
			PatternName: strings.Split(prompt.Model, ":")[0],
		}}
	}
	fabricChatReq, err := json.Marshal(chat)
	if err != nil {
		log.Printf("Error marshalling body: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}
	ctx := context.Background()
	var req *http.Request
	baseURL, err := buildFabricChatURL(*f.addr)
	if err != nil {
		log.Printf("Error building /chat URL: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	req, err = http.NewRequest("POST", fmt.Sprintf("%s/chat", baseURL), bytes.NewBuffer(fabricChatReq))
	if err != nil {
		log.Printf("Error creating /chat request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	req = req.WithContext(ctx)

	fabricRes, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error getting /chat body: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer fabricRes.Body.Close()

	if prompt.Stream {
		c.Header("Content-Type", "application/x-ndjson")
	}

	if fabricRes.StatusCode < http.StatusOK || fabricRes.StatusCode >= http.StatusMultipleChoices {
		bodyBytes, readErr := io.ReadAll(fabricRes.Body)
		if readErr != nil {
			log.Printf("Upstream Fabric server returned non-2xx status %d and body could not be read: %v", fabricRes.StatusCode, readErr)
		} else {
			log.Printf("Upstream Fabric server returned non-2xx status %d: %s", fabricRes.StatusCode, string(bodyBytes))
		}

		errorMessage := fmt.Sprintf("upstream Fabric server returned status %d", fabricRes.StatusCode)
		if prompt.Stream {
			_ = writeOllamaResponse(c, prompt.Model, fmt.Sprintf("Error: %s", errorMessage), true)
		} else {
			c.JSON(fabricRes.StatusCode, gin.H{"error": errorMessage})
		}
		return
	}

	var contentBuilder strings.Builder
	scanner := bufio.NewScanner(fabricRes.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var fabricResponse FabricResponseFormat
		if err := json.Unmarshal([]byte(payload), &fabricResponse); err != nil {
			log.Printf("Error unmarshalling body: %v", err)
			if prompt.Stream {
				// In streaming mode, send the error in the same streaming format
				_ = writeOllamaResponse(c, prompt.Model, "Error: failed to parse upstream response", true)
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unmarshal Fabric response"})
			}
			return
		}
		if fabricResponse.Type == "error" {
			if prompt.Stream {
				// In streaming mode, propagate the upstream error via a final streaming chunk
				_ = writeOllamaResponse(c, prompt.Model, fmt.Sprintf("Error: %s", fabricResponse.Content), true)
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fabricResponse.Content})
			}
			return
		}
		if fabricResponse.Type != "content" {
			continue
		}
		contentBuilder.WriteString(fabricResponse.Content)
		if prompt.Stream {
			if err := writeOllamaResponse(c, prompt.Model, fabricResponse.Content, false); err != nil {
				log.Printf("Error writing response: %v", err)
				return
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning body: %v", err)
		errorMsg := fmt.Sprintf("failed to scan SSE response stream: %v", err)
		// Check for buffer size exceeded error
		if strings.Contains(err.Error(), "token too long") {
			errorMsg = "SSE line exceeds 1MB buffer limit - data line too large"
		}
		if prompt.Stream {
			// In streaming mode, send the error in the same streaming format
			_ = writeOllamaResponse(c, prompt.Model, fmt.Sprintf("Error: %s", errorMsg), true)
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errorMsg})
		}
		return
	}

	if !prompt.Stream {
		response := OllamaResponse{
			Model:     prompt.Model,
			CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05.999999999Z"),
			Message: struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}(struct {
				Role    string
				Content string
			}{Content: contentBuilder.String(), Role: "assistant"}),
			DoneReason:         "stop",
			Done:               true,
			TotalDuration:      time.Since(now).Nanoseconds(),
			LoadDuration:       time.Since(now).Nanoseconds(),
			PromptEvalDuration: time.Since(now).Nanoseconds(),
			EvalDuration:       time.Since(now).Nanoseconds(),
		}
		c.JSON(200, response)
		return
	}

	finalResponse := OllamaResponse{
		Model:     prompt.Model,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05.999999999Z"),
		Message: struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}(struct {
			Role    string
			Content string
		}{Content: "", Role: "assistant"}),
		DoneReason:         "stop",
		Done:               true,
		TotalDuration:      time.Since(now).Nanoseconds(),
		LoadDuration:       time.Since(now).Nanoseconds(),
		PromptEvalDuration: time.Since(now).Nanoseconds(),
		EvalDuration:       time.Since(now).Nanoseconds(),
	}
	if err := writeOllamaResponseStruct(c, finalResponse); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func buildFabricChatURL(addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("empty address")
	}
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		parsed, err := url.Parse(addr)
		if err != nil {
			return "", fmt.Errorf("invalid address: %w", err)
		}
		if parsed.Host == "" {
			return "", fmt.Errorf("invalid address: missing host")
		}
		if strings.HasPrefix(parsed.Host, ":") {
			return "", fmt.Errorf("invalid address: missing hostname")
		}
		return strings.TrimRight(parsed.String(), "/"), nil
	}
	if strings.HasPrefix(addr, ":") {
		return fmt.Sprintf("http://127.0.0.1%s", addr), nil
	}
	// Validate bare addresses (without http/https prefix)
	parsed, err := url.Parse("http://" + addr)
	if err != nil {
		return "", fmt.Errorf("invalid address: %w", err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid address: missing host")
	}
	if strings.HasPrefix(parsed.Host, ":") {
		return "", fmt.Errorf("invalid address: missing hostname")
	}
	// Bare addresses should be host[:port] only - reject path components
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("invalid address: path component not allowed in bare address")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func writeOllamaResponse(c *gin.Context, model string, content string, done bool) error {
	response := OllamaResponse{
		Model:     model,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05.999999999Z"),
		Message: struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}(struct {
			Role    string
			Content string
		}{Content: content, Role: "assistant"}),
		Done: done,
	}
	return writeOllamaResponseStruct(c, response)
}

func writeOllamaResponseStruct(c *gin.Context, response OllamaResponse) error {
	marshalled, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if _, err := c.Writer.Write(marshalled); err != nil {
		return err
	}
	if _, err := c.Writer.Write([]byte("\n")); err != nil {
		return err
	}
	c.Writer.Flush()
	return nil
}
