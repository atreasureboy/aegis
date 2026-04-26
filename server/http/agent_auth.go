package http

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	servercrypto "github.com/aegis-c2/aegis/server/crypto"
	"github.com/aegis-c2/aegis/shared/protocol"
	"github.com/aegis-c2/aegis/shared/types"
)

// agentAuthContext holds the result of unified agent authentication.
type agentAuthContext struct {
	Envelope  *protocol.Envelope
	Agent     *types.Agent
	Payload   []byte // AES-GCM decrypted payload (or plaintext if no key)
	Heartbeat *protocol.HeartbeatPayload
}

// authenticateAgent performs the full auth pipeline:
// 1. Parse envelope from request body
// 2. Nonce replay check
// 3. HMAC signature verification (if agent has AES key)
// 4. AES-GCM payload decryption (if agent has AES key)
//
// Returns nil on any failure (error already written to w).
func (s *Server) authenticateAgent(w http.ResponseWriter, r *http.Request) *agentAuthContext {
	// 1. Parse envelope
	env, err := s.parseEnvelope(r)
	if err != nil {
		http.Error(w, "bad envelope", http.StatusBadRequest)
		return nil
	}

	// 2. Nonce replay check
	if s.nonceCache.Check(env.AgentID, env.Nonce) {
		http.Error(w, "replay", http.StatusForbidden)
		return nil
	}

	// 3. Look up agent
	// F-P2-2: Check the bool return value — unknown agents must be rejected
	// rather than silently proceeding with nil agent (skipping HMAC verification).
	agent, found := s.agentMgr.GetAgent(env.AgentID)
	if !found {
		s.audit.Log("UNKNOWN_AGENT", map[string]string{
			"agent_id": env.AgentID, "type": env.Type,
		})
		http.Error(w, "unknown agent", http.StatusNotFound)
		return nil
	}

	// 4. HMAC signature verification
	if hmacKey := agent.GetHMACKey(); len(hmacKey) > 0 {
		if !env.Verify(hmacKey) {
			s.audit.Log("HVERIFY_FAILED", map[string]string{
				"agent_id": env.AgentID, "type": env.Type,
			})
			http.Error(w, "bad signature", http.StatusForbidden)
			return nil
		}
	} else if key := agent.GetAESKey(); len(key) > 0 {
		// RSA fallback: use AES key for HMAC verification (backward compat)
		if !env.Verify(key) {
			s.audit.Log("HVERIFY_FAILED", map[string]string{
				"agent_id": env.AgentID, "type": env.Type,
			})
			http.Error(w, "bad signature", http.StatusForbidden)
			return nil
		}
	}

	// 5. AES-GCM decryption (skip if no key)
	payload := env.Payload
	if key := agent.GetAESKey(); len(key) > 0 {
		decrypted, err := servercrypto.DecryptAESGCM(key, env.Nonce, payload)
		if err != nil {
			s.audit.Log("DECRYPT_FAILED", map[string]string{
				"agent_id": env.AgentID, "type": env.Type, "error": err.Error(),
			})
			log.Printf("[HEARTBEAT DEBUG] AES-GCM decrypt failed for agent %s, type=%s: %v", env.AgentID, env.Type, err)
			http.Error(w, "decryption failed", http.StatusForbidden)
			return nil
		}
		payload = decrypted
	}

	return &agentAuthContext{
		Envelope: env,
		Agent:    agent,
		Payload:  payload,
	}
}

// parseHeartbeat unmarshals ctx.Payload as HeartbeatPayload.
// Returns nil on failure (error already written to w).
func (s *Server) parseHeartbeat(ctx *agentAuthContext, w http.ResponseWriter) *protocol.HeartbeatPayload {
	var hb protocol.HeartbeatPayload
	if err := json.Unmarshal(ctx.Payload, &hb); err != nil {
		s.audit.Log("HEARTBEAT_PARSE_ERROR", map[string]string{
			"agent_id": ctx.Agent.ID,
			"error":    err.Error(),
			"raw_len":  fmt.Sprintf("%d", len(ctx.Payload)),
		})
		log.Printf("[HEARTBEAT DEBUG] parse failed for agent %s: raw payload len=%d, error=%v, first 64 bytes: %q",
			ctx.Agent.ID, len(ctx.Payload), err, ctx.Payload[:min(64, len(ctx.Payload))])
		http.Error(w, "bad payload", http.StatusBadRequest)
		return nil
	}
	ctx.Heartbeat = &hb
	return &hb
}
