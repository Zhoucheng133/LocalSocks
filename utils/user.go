package utils

import (
	"database/sql"
	"errors"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/bcrypt"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GET /api/init
func HandleInit(c fiber.Ctx) error {
	count, err := countUsers()
	if err != nil {
		return Respond(c, false, err.Error())
	}
	return Respond(c, true, count == 0)
}

// POST /api/register
func HandleRegister(c fiber.Ctx) error {
	count, err := countUsers()
	if err != nil {
		return Respond(c, false, err.Error())
	}
	if count > 0 {
		return Respond(c, false, "user already exists")
	}

	var body credentials
	if err := c.Bind().Body(&body); err != nil {
		return Respond(c, false, "failed to parse request body")
	}
	if body.Username == "" || body.Password == "" {
		return Respond(c, false, "username or password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return Respond(c, false, err.Error())
	}

	id, err := gonanoid.New()
	if err != nil {
		return Respond(c, false, err.Error())
	}

	if _, err := db.Exec(
		`INSERT INTO user (id, username, password) VALUES (?, ?, ?)`,
		id, body.Username, string(hash),
	); err != nil {
		return Respond(c, false, err.Error())
	}

	return Respond(c, true, fiber.Map{
		"id":       id,
		"username": body.Username,
	})
}

// POST /api/login
func HandleLogin(c fiber.Ctx) error {
	count, err := countUsers()
	if err != nil {
		return Respond(c, false, err.Error())
	}
	if count == 0 {
		return Respond(c, false, "no user exists")
	}

	var body credentials
	if err := c.Bind().Body(&body); err != nil {
		return Respond(c, false, "failed to parse request body")
	}
	if body.Username == "" || body.Password == "" {
		return Respond(c, false, "username or password cannot be empty")
	}

	var id, hash string
	err = db.QueryRow(
		`SELECT id, password FROM user WHERE username = ?`,
		body.Username,
	).Scan(&id, &hash)
	if err == sql.ErrNoRows {
		return Respond(c, false, "user not found")
	}
	if err != nil {
		return Respond(c, false, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		return Respond(c, false, "incorrect password")
	}

	accessToken, err := GenerateAccessToken(id, body.Username)
	if err != nil {
		return Respond(c, false, err.Error())
	}
	refreshToken, err := GenerateRefreshToken(id, body.Username)
	if err != nil {
		return Respond(c, false, err.Error())
	}
	SetRefreshTokenCookie(c, refreshToken)

	return Respond(c, true, accessToken)
}

// GET /api/refresh
func HandleRefresh(c fiber.Ctx) error {
	token := c.Cookies(cookieName)
	if token == "" {
		return Respond(c, false, "missing refresh token")
	}

	claims, err := ValidateRefreshToken(token)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return Respond(c, false, "expired")
		}
		return Respond(c, false, "invalid refresh token")
	}

	accessToken, err := GenerateAccessToken(claims.ID, claims.Username)
	if err != nil {
		return Respond(c, false, err.Error())
	}

	return Respond(c, true, accessToken)
}

// POST /api/user/edit
func HandleUserEdit(c fiber.Ctx) error {
	var body credentials
	if err := c.Bind().Body(&body); err != nil {
		return Respond(c, false, "failed to parse request body")
	}
	if body.Username == "" || body.Password == "" {
		return Respond(c, false, "username or password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return Respond(c, false, err.Error())
	}

	var id string
	err = db.QueryRow(`SELECT id FROM user LIMIT 1`).Scan(&id)
	if err == sql.ErrNoRows {
		return Respond(c, false, "no user exists")
	}
	if err != nil {
		return Respond(c, false, err.Error())
	}

	if _, err := db.Exec(
		`UPDATE user SET username = ?, password = ? WHERE id = ?`,
		body.Username, string(hash), id,
	); err != nil {
		return Respond(c, false, err.Error())
	}

	ClearRefreshTokenCookie(c)

	return Respond(c, true, fiber.Map{
		"id":       id,
		"username": body.Username,
	})
}

// ALL /api/auth
func HandleAuth(c fiber.Ctx) error {
	claims, err := AuthFromHeader(c)
	if err != nil {
		return Respond(c, false, err.Error())
	}

	return Respond(c, true, fiber.Map{
		"id":       claims.ID,
		"username": claims.Username,
	})
}
