package utils

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/matoous/go-nanoid/v2"
)

const (
	envFile          = "./db/.env"
	refreshSecretKey = "refresh_secret"
	accessSecretKey  = "access_secret"

	cookieName = "localsocks_refresh_token"
	cookiePath = "/api/refresh"

	refreshTTL = 30 * 24 * time.Hour
	accessTTL  = 30 * time.Minute

	tokenHeader = "token"
)

var (
	refreshSecret []byte
	accessSecret  []byte
)

type Claims struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func InitAuth() error {
	content := ""
	if data, err := os.ReadFile(envFile); err == nil {
		content = string(data)
	}

	values := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	added := false
	for _, key := range []string{refreshSecretKey, accessSecretKey} {
		if values[key] != "" {
			continue
		}
		id, err := gonanoid.New()
		if err != nil {
			return err
		}
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += key + "=" + id + "\n"
		values[key] = id
		added = true
	}

	if added || content == "" {
		if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
			return err
		}
	}

	refreshSecret = []byte(values[refreshSecretKey])
	accessSecret = []byte(values[accessSecretKey])
	return nil
}

func generateToken(secret []byte, ttl time.Duration, id, username string) (string, error) {
	now := time.Now()
	claims := Claims{
		ID:       id,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func GenerateRefreshToken(id, username string) (string, error) {
	return generateToken(refreshSecret, refreshTTL, id, username)
}

func GenerateAccessToken(id, username string) (string, error) {
	return generateToken(accessSecret, accessTTL, id, username)
}

func parseToken(tokenStr string, secret []byte) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// ValidateAccessToken validates an access token and returns its claims.
// It is exported so other APIs can reuse it.
func ValidateAccessToken(tokenStr string) (*Claims, error) {
	return parseToken(tokenStr, accessSecret)
}

func ValidateRefreshToken(tokenStr string) (*Claims, error) {
	return parseToken(tokenStr, refreshSecret)
}

// AuthFromHeader validates the access token carried in the "token" header.
func AuthFromHeader(c fiber.Ctx) (*Claims, error) {
	token := strings.TrimSpace(c.Get(tokenHeader))
	if token == "" {
		return nil, errors.New("missing token")
	}
	claims, err := ValidateAccessToken(token)
	if err != nil {
		return nil, errors.New("invalid or expired token")
	}
	return claims, nil
}

// RequireAuth is a middleware that guards routes with AuthFromHeader.
func RequireAuth(c fiber.Ctx) error {
	if _, err := AuthFromHeader(c); err != nil {
		return Respond(c, false, err.Error())
	}
	return c.Next()
}

// SetRefreshTokenCookie writes the refresh token into a cookie scoped to /api/refresh.
func SetRefreshTokenCookie(c fiber.Ctx, token string) {
	c.Cookie(&fiber.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     cookiePath,
		MaxAge:   int(refreshTTL.Seconds()),
		HTTPOnly: true,
		Secure:   false,
	})
}

// ClearRefreshTokenCookie removes the refresh token cookie.
func ClearRefreshTokenCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     cookieName,
		Path:     cookiePath,
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   false,
	})
}
