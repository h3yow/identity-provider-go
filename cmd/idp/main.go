// Command idp runs the in-process identity provider with an HTTP API.
//
// All state (key versions, sessions, refresh chains) lives in process memory;
// restarting resets it. It is intended for local exercise and verification.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/h3yow/identity-provider-go/internal/auth"
	"github.com/h3yow/identity-provider-go/internal/authz"
	"github.com/h3yow/identity-provider-go/internal/keys"
	"github.com/h3yow/identity-provider-go/internal/server"
	"github.com/h3yow/identity-provider-go/internal/tokens"
)

func main() {
	logger := log.New(os.Stdout, "idp ", log.LstdFlags|log.Lmicroseconds)
	now := time.Now()

	// Bootstrap two coexisting key versions: v1 is near the end of its signing
	// life but still verifies (grace window), v2 is the active signing key.
	ring := keys.NewKeyRing()
	v1, err := ring.Rotate("v1", []byte("local-bootstrap-secret-v1"), now.Add(-55*time.Minute), time.Hour, 2*time.Hour)
	if err != nil {
		log.Fatalf("bootstrap v1: %v", err)
	}
	v2, err := ring.Rotate("v2", []byte("local-bootstrap-secret-v2"), now, time.Hour, 2*time.Hour)
	if err != nil {
		log.Fatalf("bootstrap v2: %v", err)
	}
	logger.Printf("key ring ready: %s(grace until %s), %s(active until %s)",
		v1.ID, v1.RetireAt.Format(time.RFC3339), v2.ID, v2.ExpiresAt.Format(time.RFC3339))

	signer := tokens.NewSigner(ring)
	authSvc := auth.NewService(signer, auth.Options{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		// Demo capacity gate: at most 8 live session chains per subject.
		MaxChainsPerSubject: 8,
		Logger:              logger,
	})

	// Demo RBAC policy: roles map to granted scopes.
	policy := authz.NewPolicy()
	policy.Grant("viewer", "read")
	policy.Grant("editor", "read", "write")
	policy.Grant("admin", "read", "write", "admin")
	authorizer := authz.NewAuthorizer(authSvc, policy, logger)

	srv := server.New(server.Config{Auth: authSvc, Authz: authorizer})
	addr := ":8080"
	if p := os.Getenv("IDP_ADDR"); p != "" {
		addr = p
	}
	logger.Printf("listening on %s (endpoints: /login /refresh /logout /terminate /verify /authz)", addr)
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}
