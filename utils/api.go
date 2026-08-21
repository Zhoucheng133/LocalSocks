package utils

import (
	"database/sql"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/bcrypt"

	"github.com/matoous/go-nanoid/v2"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func respond(c fiber.Ctx, ok bool, data any) error {
	return c.JSON(fiber.Map{
		"ok":   ok,
		"data": data,
	})
}

// GET /api/init
func HandleInit(c fiber.Ctx) error {
	count, err := countUsers()
	if err != nil {
		return respond(c, false, err.Error())
	}
	return respond(c, true, count == 0)
}

// POST /api/register
func HandleRegister(c fiber.Ctx) error {
	count, err := countUsers()
	if err != nil {
		return respond(c, false, err.Error())
	}
	if count > 0 {
		return respond(c, false, "user already exists")
	}

	var body credentials
	if err := c.Bind().Body(&body); err != nil {
		return respond(c, false, "failed to parse request body")
	}
	if body.Username == "" || body.Password == "" {
		return respond(c, false, "username or password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return respond(c, false, err.Error())
	}

	id, err := gonanoid.New()
	if err != nil {
		return respond(c, false, err.Error())
	}

	if _, err := db.Exec(
		`INSERT INTO user (id, username, password) VALUES (?, ?, ?)`,
		id, body.Username, string(hash),
	); err != nil {
		return respond(c, false, err.Error())
	}

	return respond(c, true, fiber.Map{
		"id":       id,
		"username": body.Username,
	})
}

// POST /api/login
func HandleLogin(c fiber.Ctx) error {
	count, err := countUsers()
	if err != nil {
		return respond(c, false, err.Error())
	}
	if count == 0 {
		return respond(c, false, "no user exists")
	}

	var body credentials
	if err := c.Bind().Body(&body); err != nil {
		return respond(c, false, "failed to parse request body")
	}
	if body.Username == "" || body.Password == "" {
		return respond(c, false, "username or password cannot be empty")
	}

	var id, hash string
	err = db.QueryRow(
		`SELECT id, password FROM user WHERE username = ?`,
		body.Username,
	).Scan(&id, &hash)
	if err == sql.ErrNoRows {
		return respond(c, false, "user not found")
	}
	if err != nil {
		return respond(c, false, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)); err != nil {
		return respond(c, false, "incorrect password")
	}

	return respond(c, true, fiber.Map{
		"id":       id,
		"username": body.Username,
	})
}
