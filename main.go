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

	utils.AutoStartRunning()

	app := fiber.New()

	app.Get("/api/init", utils.HandleInit)
	app.Post("/api/register", utils.HandleRegister)
	app.Post("/api/login", utils.HandleLogin)
	app.Get("/api/refresh", utils.HandleRefresh)
	app.All("/api/auth", utils.HandleAuth)

	protected := app.Group("/api", utils.RequireAuth)
	protected.Post("/user/edit", utils.HandleUserEdit)
	protected.Get("/server/list", utils.HandleServerList)
	protected.Post("/server/add", utils.HandleServerAdd)
	protected.Delete("/server/del/:id", utils.HandleServerDel)
	protected.Post("/server/edit/:id", utils.HandleServerEdit)

	protected.Post("/server/run/:id", utils.RunSocks)
	protected.Post("/server/stop", utils.StopSocks)

	protected.Get("/server/cert", utils.DownloadCert)
	protected.Get("/server/fingerprint", utils.GetCertFingerprint)
	protected.Get("/server/remain", utils.GetCertRemaining)

	log.Fatal(app.Listen(":8080"))
}
