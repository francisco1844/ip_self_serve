package main

import (
	"ip_self_serve/handlers"

	"github.com/labstack/echo/v4"
)

func main() {
	// Echo instance
	e := echo.New()

	// Static folders
	e.Static("/css", "css")

	e.GET("/", handlers.RootHandler)
	e.POST("/validate", handlers.ValidateHandler, handlers.IPRateLimit())
	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}
