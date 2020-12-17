package handlers

import (
	"fmt"
	"ip_self_serve/src/ipss_html"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

func RootHandler(c echo.Context) error {
	return c.HTML(http.StatusOK, ipss_html.HTMLroot())

}

func ValidateHandler(c echo.Context) error {

	var ypass, ytrivial_password, yuser string
	viper.SetConfigName("ipss_config") // name of config file (without extension)
	viper.AddConfigPath("$HOME/")      // path to config, call multiple times to add many search paths
	viper.AddConfigPath(".")           // optionally look for config in the working directory
	err := viper.ReadInConfig()        // Find and read the config file
	if err != nil {                    // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error reading config file: %s \n", err))
	}
	ytrivial_password = viper.Get("trivial_password").(string)
	ypass = viper.Get("password").(string)
	yuser = viper.Get("user").(string)

	uname := c.FormValue("username")
	pass := c.FormValue("password")
	trivial := c.FormValue("trivial_password")
	return c.HTML(http.StatusOK, validate_vars(ypass, ytrivial_password, yuser, pass, trivial, uname, c))

}

func validate_vars(ypass, ytrivial_password, yuser, pass, trivial, uname string,c echo.Context) string {
	var returnHTML string
	if ytrivial_password == trivial && yuser == uname && ypass == pass {
		ip := c.RealIP()
		returnHTML = fmt.Sprintf("<br> The IP Address is ", ip)
	} else {
		returnHTML = "failed"
	}

	return returnHTML

}
