package utils

import (
	"database/sql"
	"strings"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/bcrypt"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

type serverPayload struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// POST /api/server/add
func HandleServerAdd(c fiber.Ctx) error {
	var body serverPayload
	if err := c.Bind().Body(&body); err != nil {
		return Respond(c, false, "failed to parse request body")
	}
	if body.Name == "" || body.Host == "" || body.Username == "" || body.Password == "" {
		return Respond(c, false, "name, host, username or password cannot be empty")
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
		`INSERT INTO server (id, name, host, username, password) VALUES (?, ?, ?, ?, ?)`,
		id, body.Name, body.Host, body.Username, string(hash),
	); err != nil {
		return Respond(c, false, err.Error())
	}

	return Respond(c, true, fiber.Map{
		"id":       id,
		"name":     body.Name,
		"host":     body.Host,
		"username": body.Username,
	})
}

// DELETE /api/server/del/:id
func HandleServerDel(c fiber.Ctx) error {
	id := c.Params("id")

	var running int
	err := db.QueryRow(`SELECT running FROM server WHERE id = ?`, id).Scan(&running)
	if err == sql.ErrNoRows {
		return Respond(c, false, "server not found")
	}
	if err != nil {
		return Respond(c, false, err.Error())
	}
	if running != 0 {
		return Respond(c, false, "server is running")
	}

	if _, err := db.Exec(`DELETE FROM server WHERE id = ?`, id); err != nil {
		return Respond(c, false, err.Error())
	}

	return Respond(c, true, "deleted")
}

// POST /api/server/edit/:id
func HandleServerEdit(c fiber.Ctx) error {
	id := c.Params("id")

	var body serverPayload
	if err := c.Bind().Body(&body); err != nil {
		return Respond(c, false, "failed to parse request body")
	}

	var sets []string
	var args []any
	if body.Name != "" {
		sets = append(sets, "name = ?")
		args = append(args, body.Name)
	}
	if body.Host != "" {
		sets = append(sets, "host = ?")
		args = append(args, body.Host)
	}
	if body.Username != "" {
		sets = append(sets, "username = ?")
		args = append(args, body.Username)
	}
	if body.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			return Respond(c, false, err.Error())
		}
		sets = append(sets, "password = ?")
		args = append(args, string(hash))
	}
	if len(sets) == 0 {
		return Respond(c, false, "nothing to update")
	}

	args = append(args, id)
	res, err := db.Exec(`UPDATE server SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	if err != nil {
		return Respond(c, false, err.Error())
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return Respond(c, false, "server not found")
	}

	return Respond(c, true, "updated")
}
