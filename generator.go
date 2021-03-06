package generator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/url"
	"time"
)

// TokenOptions contains the options for the token generated
type TokenOptions struct {
	SignedPermissions     string
	SignedStart           string
	SignedExpiry          string
	CanonicalizedResource string
	SignedIdentifier      string
	SignedIP              string
	SignedProtocol        string
	SignedVersion         string
	SignedResource        string
	SignedSnapshotTime    string
	Rscc                  string
	Rscd                  string
	Rsce                  string
	Rscl                  string
	Rsct                  string
}

// GenerateToken returns a token using the given content URI and access key
func GenerateToken(options *TokenOptions, sasKey string) string {

	stringToSign := options.SignedPermissions + "\n" +
		options.SignedStart + "\n" +
		options.SignedExpiry + "\n" +
		options.CanonicalizedResource + "\n" +
		options.SignedIdentifier + "\n" +
		options.SignedIP + "\n" +
		options.SignedProtocol + "\n" +
		options.SignedVersion + "\n" +
		options.SignedResource + "\n" +
		options.SignedSnapshotTime + "\n" +
		options.Rscc + "\n" +
		options.Rscd + "\n" +
		options.Rsce + "\n" +
		options.Rscl + "\n" +
		options.Rsct

	rawSig := getHmac256(stringToSign, sasKey)

	sig := template.URLQueryEscaper(rawSig)

	return fmt.Sprintf("sv=%s&sp=%s&sr=%s&spr=%s&se=%s&sig=%s",
		options.SignedVersion,
		options.SignedPermissions,
		options.SignedResource,
		options.SignedProtocol,
		options.SignedExpiry,
		sig)
}

// GenerateSignedExpiry returns a valid expiration string x minutes from now
// The expiration string is in UTC, formatted in RFC3339 (YYYY-MM-DDThh:mm:ssZ)
func GenerateSignedExpiry(minutes int) string {
	// Format expire time
	expireTime := time.Now().Add(time.Duration(minutes) * time.Minute)
	// Signed Expiry
	return expireTime.UTC().Format(time.RFC3339)
}

// GenerateCanonicalizedResource returns a canonicalized resource string
func GenerateCanonicalizedResource(uri string, service string) string {
	u, _ := url.Parse(uri)

	return "/blob/" + service + u.Path
}

func getHmac256(str string, secret string) string {
	str, err := url.QueryUnescape(str)
	if err != nil {
		fmt.Println("Error QueryUnescape-ing string to sign")
	}
	data, _ := base64.StdEncoding.DecodeString(secret)
	key := []byte(data)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
