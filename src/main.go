package main

import (
	"fmt"
	"ip_self_serve/src/handlers"
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {
	// Echo instance
	e := echo.New()

	// Static folders
	e.Static("/css", "css")

	e.GET("/", handlers.rootHandler)
	//        e.GET("/matchPass", simpleMatch)
	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}
