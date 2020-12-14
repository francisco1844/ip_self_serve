package handlers

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

var ypass, ytrivial_password, yuser string

func rootHandler(c echo.Context) error {
	viper.SetConfigName("ipss_config") // name of config file (without extension)
	viper.AddConfigPath("$HOME/")      // path to config, call multiple times to add many search paths
	viper.AddConfigPath(".")           // optionally look for config in the working directory
	err := viper.ReadInConfig()        // Find and read the config file
	if err != nil {                    // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error reading config file: %s \n", err))
	}
	ytrivial_password = viper.Get("trivial_password").(string)
	ypassword = viper.Get("password").(string)
	yuser = viper.Get("user").(string)

	uname := c.FormValue("username")
	Pass = c.FormValue("password")
	if uname != "" {
		matchPass(c)
	} else {
		return c.HTML(http.StatusOK, LoginHTML+"Username cannot be blank")
	}
	return c.HTML(http.StatusOK, "<br>")
}

func matchPass(c echo.Context) error {
	if Pass == password {
		ip := c.RealIP()
		return c.HTML(http.StatusOK, LoginHTML+"<br> The IP Address is "+ip)
	} else {
		return c.HTML(http.StatusOK, LoginHTML+"<br> The simple password did not match")
	}
}
