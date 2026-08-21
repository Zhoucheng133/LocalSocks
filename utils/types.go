package utils

import "github.com/gofiber/fiber/v3"

func Respond(c fiber.Ctx, ok bool, data any) error {
	return c.JSON(fiber.Map{
		"ok":   ok,
		"data": data,
	})
}
