package main

import (
	"log"

	"github.com/gofiber/fiber/v3"

	"local_socks/utils"
)

func main() {
	if err := utils.InitDB(); err != nil {
		log.Fatal("failed to init database: ", err)
	}
	defer utils.CloseDB()

	if err := utils.InitAuth(); err != nil {
		log.Fatal("failed to init auth: ", err)
	}

	app := fiber.New()

	app.Get("/api/init", utils.HandleInit)
	app.Post("/api/register", utils.HandleRegister)
	app.Post("/api/login", utils.HandleLogin)
	app.Get("/api/refresh", utils.HandleRefresh)
	app.All("/api/auth", utils.HandleAuth)

	log.Fatal(app.Listen(":8080"))
}
