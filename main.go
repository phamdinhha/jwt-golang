package main

import (
	"example/jwt/routes"

	"example/jwt/database"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {

	//mysql connection
	database.Connect()

	//redis connection
	redis_host := "localhost"
	redis_port := "6379"
	redis_pass := ""
	database.NewRedisDB(redis_host, redis_port, redis_pass)

	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
	}))
	routes.Setup(app)
	app.Listen(":8000")
}
