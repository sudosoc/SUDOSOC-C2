package web

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif
	Web API: AI chat endpoint — bridges the Web UI to the server-side AI provider.
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	serverai "github.com/sudosoc/SUDOSOC-C2/server/ai"
	"github.com/sudosoc/SUDOSOC-C2/server/configs"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
)

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/ai/chat
// Body:    { "messages": [{role, content}], "context": "..." }
// Returns: { "reply": "...", "model": "...", "provider": "..." }
// ─────────────────────────────────────────────────────────────────────────────

type aiChatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiChatReq struct {
	Messages []aiChatMsg `json:"messages"`
	Context  string      `json:"context,omitempty"` // optional extra context injected into system prompt
}

type aiChatResp struct {
	Reply    string `json:"reply"`
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
	Error    string `json:"error,omitempty"`
}

func handleAIChat(w http.ResponseWriter, r *http.Request) {
	var req aiChatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.Messages) == 0 {
		jsonError(w, "messages required", http.StatusBadRequest)
		return
	}

	// ── Build runtime config from server AI settings ─────────────────────
	serverCfg := configs.GetServerConfig()
	runtime, err := serverai.ResolveRuntimeConfig(serverCfg, nil)
	if err != nil {
		jsonError(w, fmt.Sprintf("AI not configured: %v — configure an AI provider in server config", err), http.StatusServiceUnavailable)
		return
	}

	// ── Build context-aware system prompt ────────────────────────────────
	systemPrompt := buildWebAISystemPrompt(req.Context)

	// ── Convert messages to protobuf format ──────────────────────────────
	pbMsgs := make([]*clientpb.AIConversationMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := strings.ToLower(m.Role)
		if role != "user" && role != "assistant" {
			continue
		}
		content := strings.TrimSpace(m.Content)
		if content == "" {
			continue
		}
		pbMsgs = append(pbMsgs, &clientpb.AIConversationMessage{
			Role:    role,
			Content: content,
			Kind:    clientpb.AIConversationMessageKind_AI_MESSAGE_KIND_CHAT,
		})
	}
	if len(pbMsgs) == 0 {
		jsonError(w, "no valid messages", http.StatusBadRequest)
		return
	}

	conversation := &clientpb.AIConversation{
		SystemPrompt: systemPrompt,
		Messages:     pbMsgs,
	}

	// ── Call AI provider ─────────────────────────────────────────────────
	completion, err := serverai.CompleteConversation(context.Background(), runtime, conversation)
	if err != nil {
		jsonError(w, fmt.Sprintf("AI request failed: %v", err), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(aiChatResp{
		Reply:    completion.Content,
		Model:    runtime.Model,
		Provider: runtime.Provider,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/ai/status
// Returns current AI provider status (configured / not configured)
// ─────────────────────────────────────────────────────────────────────────────

type aiStatusResp struct {
	Configured bool   `json:"configured"`
	Provider   string `json:"provider,omitempty"`
	Model      string `json:"model,omitempty"`
	Message    string `json:"message,omitempty"`
}

func handleAIStatus(w http.ResponseWriter, r *http.Request) {
	serverCfg := configs.GetServerConfig()
	runtime, err := serverai.ResolveRuntimeConfig(serverCfg, nil)
	if err != nil {
		_ = json.NewEncoder(w).Encode(aiStatusResp{
			Configured: false,
			Message:    err.Error(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(aiStatusResp{
		Configured: true,
		Provider:   runtime.Provider,
		Model:      runtime.Model,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func buildWebAISystemPrompt(extraContext string) string {
	const base = `You are SUDOSOC-C2's AI copilot for authorized security testing, detection engineering, lab work, and incident-response support in environments the operator is explicitly permitted to assess.

Your job is to help the operator make careful, high-signal decisions inside the SUDOSOC-C2 workflow.

Operating rules:
- Assume all activity must stay within the operator's authorized scope.
- Use the current conversation and target metadata to tailor answers.
- Never fabricate command output, host state, credentials, files, loot, or tool results.
- Prefer the smallest next step that increases certainty.
- Highlight operational tradeoffs: stealth, telemetry, privilege requirements, target stability.
- When suggesting commands, make them concrete, minimal, and easy to audit.

Response style:
- Be concise, structured, and operator-focused.
- Prefer short checklists or step plans over long essays.
- Distinguish clearly between facts, assumptions, and recommendations.
- If the request appears outside authorized security work, refuse and redirect.`

	if strings.TrimSpace(extraContext) == "" {
		return base
	}

	// Inject live context (sessions, OS info, etc.) from the Web UI
	return base + "\n\n─── Current C2 Context ───\n" + extraContext
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/settings/ai  — return current AI config (key masked)
// POST /api/settings/ai — save AI provider config
// ─────────────────────────────────────────────────────────────────────────────

type aiSettingsReq struct {
	Provider string `json:"provider"`          // openrouter, openai, openai-compat, anthropic
	APIKey   string `json:"api_key"`            // raw key — stored securely in config file
	Model    string `json:"model,omitempty"`
	BaseURL  string `json:"base_url,omitempty"` // for openai-compat
}

type aiSettingsResp struct {
	Provider     string `json:"provider"`
	Model        string `json:"model,omitempty"`
	BaseURL      string `json:"base_url,omitempty"`
	APIKeyMasked string `json:"api_key_masked,omitempty"` // e.g. "sk-…abc" — never return real key
}

func handleGetAISettings(w http.ResponseWriter, r *http.Request) {
	cfg := configs.GetServerConfig()
	if cfg.AI == nil {
		_ = json.NewEncoder(w).Encode(aiSettingsResp{})
		return
	}
	resp := aiSettingsResp{
		Provider: cfg.AI.Provider,
		Model:    cfg.AI.Model,
	}
	// Return masked key + base URL for the active provider
	var provCfg *configs.AIProviderConfig
	switch cfg.AI.Provider {
	case "openrouter":
		provCfg = cfg.AI.OpenRouter
	case "openai":
		provCfg = cfg.AI.OpenAI
	case "openai-compat":
		provCfg = cfg.AI.OpenAICompat
	case "anthropic":
		provCfg = cfg.AI.Anthropic
	}
	if provCfg != nil {
		resp.BaseURL = provCfg.BaseURL
		if provCfg.APIKey != "" {
			k := provCfg.APIKey
			if len(k) > 8 {
				resp.APIKeyMasked = k[:4] + "…" + k[len(k)-4:]
			} else {
				resp.APIKeyMasked = "****"
			}
		}
		if len(provCfg.Models) > 0 && resp.Model == "" {
			resp.Model = provCfg.Models[0]
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func handleSaveAISettings(w http.ResponseWriter, r *http.Request) {
	var req aiSettingsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Provider == "" {
		jsonError(w, "provider is required", http.StatusBadRequest)
		return
	}

	cfg := configs.GetServerConfig()
	if cfg.AI == nil {
		cfg.AI = &configs.AIConfig{}
	}
	cfg.AI.Provider = req.Provider
	if req.Model != "" {
		cfg.AI.Model = req.Model
	}

	// Build provider-specific config
	provCfg := &configs.AIProviderConfig{
		APIKey:  req.APIKey,
		BaseURL: req.BaseURL,
	}
	if req.Model != "" {
		provCfg.Models = []string{req.Model}
	}

	switch req.Provider {
	case "openrouter":
		if provCfg.BaseURL == "" {
			provCfg.BaseURL = "https://openrouter.ai/api/v1"
		}
		cfg.AI.OpenRouter = provCfg
	case "openai":
		cfg.AI.OpenAI = provCfg
	case "openai-compat":
		cfg.AI.OpenAICompat = provCfg
	case "anthropic":
		cfg.AI.Anthropic = provCfg
	default:
		jsonError(w, fmt.Sprintf("unsupported provider %q", req.Provider), http.StatusBadRequest)
		return
	}

	if err := cfg.Save(); err != nil {
		jsonError(w, fmt.Sprintf("failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":   "saved",
		"provider": req.Provider,
		"model":    req.Model,
	})
}

// buildAIContext builds a context string from live session/beacon data
// to inject into the system prompt so the AI has situational awareness.
func buildAIContext() string {
	sessions := core.Sessions.All()
	if len(sessions) == 0 {
		return "No active sessions."
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Active sessions: %d\n", len(sessions)))
	for i, s := range sessions {
		if i >= 5 { // Limit context size
			sb.WriteString(fmt.Sprintf("… and %d more\n", len(sessions)-5))
			break
		}
		sb.WriteString(fmt.Sprintf("  • %s  %s/%s  %s@%s  [%s]  %s\n",
			s.Name, s.OS, s.Arch, s.Username, s.Hostname,
			s.Connection.Transport, s.ActiveC2))
	}
	return sb.String()
}
