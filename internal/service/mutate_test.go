package service

import (
	"encoding/base64"
	"strings"
)

var rawB64 = base64.RawURLEncoding

func mutateKidHelper(raw, kid string) string {
	parts := strings.Split(raw, ".")
	parts[1] = rawB64.EncodeToString([]byte(kid))
	return strings.Join(parts, ".")
}
