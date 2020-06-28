package generator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
  "html/template"
	"os"
	"time"
)

// TokenOptions contains the options for the token generated
type TokenOptions struct {
  signedPermissions string
  signedStart string
  signedExpiry string
  canonicalizedResource string
  signedIdentifier string
  signedIP string
  signedProtocol string
  signedVersion string
  signedResource string
  signedSnapshotTime string
  rscc string
  rscd string
  rsce string
  rscl string
  rsct string
}

// GenerateToken returns a token using the given resource URI and access key
func GenerateToken(options *TokenOptions, sasKey string) string {

  stringToSign := options.signedPermissions + "\n" +
                  options.signedStart + "\n" +
                  options.signedExpiry + "\n" +
                  options.canonicalizedResource + "\n" +
                  options.signedIdentifier + "\n" +
                  options.signedIP + "\n" +
                  options.signedProtocol + "\n" +
                  options.signedVersion + "\n" +
                  options.signedResource + "\n" +
                  options.signedSnapshotTime + "\n" +
                  options.rscc + "\n" +
                  options.rscd + "\n" +
                  options.rsce + "\n" +
                  options.rscl + "\n" +
                  options.rsct

  fmt.Println("String to sign: " + stringToSign)

	rawSig := getHmac256(stringToSign, sasKey)
	sig := template.URLQueryEscaper(rawSig)

	return fmt.Sprintf("sv=%s&sp=%s&sr=%s&spr=%s&se=%s&sig=%s",
    options.signedVersion,
    options.signedPermissions,
    options.signedResource,
    options.signedProtocol,
    options.signedExpiry,
    sig)
}

// GenerateSignedExpiry returns a valid expiration string in x minutes
func GenerateSignedExpiry (minutes int) string {
	// Format expire time
	expireTime := time.Now().Add(time.Duration(minutes) * time.Minute)
	// Signed Expiry
  return expireTime.UTC().Format(time.RFC3339)
}

// GenerateCanonicalizedResource returns a canonicalized resource string
func GenerateCanonicalizedResource (uri string) string {
  u, err := url.Parse(uri)

  if err != nil {
    panic(err)
  }

  return "/blob/" + os.Getenv("SAS_SERVICE") + u.Path
}

func getHmac256(str string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

