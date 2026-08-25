package utils

import (
	"strings"

	"github.com/gofiber/fiber/v3"

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

	enc, err := Encrypt(body.Password, serverSecret)
	if err != nil {
		return Respond(c, false, err.Error())
	}

	id, err := gonanoid.New()
	if err != nil {
		return Respond(c, false, err.Error())
	}

	if _, err := db.Exec(
		`INSERT INTO server (id, name, host, username, password) VALUES (?, ?, ?, ?, ?)`,
		id, body.Name, body.Host, body.Username, enc,
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

// GET /api/server/list
func HandleServerList(c fiber.Ctx) error {
	rows, err := db.Query(`SELECT id, name, host, username FROM server`)
	if err != nil {
		return Respond(c, false, err.Error())
	}
	defer rows.Close()

	var currentRunning string
	if err := db.QueryRow(`SELECT running FROM config`).Scan(&currentRunning); err != nil {
		return Respond(c, false, err.Error())
	}

	servers := []fiber.Map{}
	for rows.Next() {
		var id, name, host, username string
		if err := rows.Scan(&id, &name, &host, &username); err != nil {
			return Respond(c, false, err.Error())
		}
		servers = append(servers, fiber.Map{
			"id":       id,
			"name":     name,
			"host":     host,
			"username": username,
			"running":  id == currentRunning,
		})
	}
	if err := rows.Err(); err != nil {
		return Respond(c, false, err.Error())
	}

	return Respond(c, true, servers)
}

// DELETE /api/server/del/:id
func HandleServerDel(c fiber.Ctx) error {
	id := c.Params("id")

	var running string
	err := db.QueryRow(`SELECT running FROM config`).Scan(&running)
	if err != nil {
		return Respond(c, false, err.Error())
	}
	if running == id {
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
		enc, err := Encrypt(body.Password, serverSecret)
		if err != nil {
			return Respond(c, false, err.Error())
		}
		sets = append(sets, "password = ?")
		args = append(args, enc)
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
