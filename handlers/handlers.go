package handlers

import (
	"fmt"
	"ip_self_serve/ipss_html"
	"net/http"

	"encoding/csv"
	"log"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

var uname, ip string

func RootHandler(c echo.Context) error {
	return c.HTML(http.StatusOK, ipss_html.HTMLroot())

}

func ValidateHandler(c echo.Context) error {

	var ypass, ytrivial_password_format, returnHTML string

	uname = c.FormValue("username")
	pass := c.FormValue("password")
	trivial := c.FormValue("trivial_password")
	viper_path()
	ytrivial_password_format = viper.GetString("trivial_password")
	ypass = viper.GetString("users." + uname + ".password")
	computed_trivial := trivial_password(ytrivial_password_format)
	if trivial != computed_trivial {
		returnHTML = "Invalid trivial password - got " + trivial + " computed " + computed_trivial
	} else if ypass == "" {
		returnHTML = ipss_html.HTMLfailed()
	} else {
		returnHTML = validate_vars(ypass, uname, pass, uname, c)
	}

	return c.HTML(http.StatusOK, returnHTML)

}

func validate_vars(ypass, yuser, pass, uname string, c echo.Context) string {
	var returnHTML string
	viper_path()
	csvname := viper.Get("csv").(string)

	if yuser == uname && ypass == pass {
		ip = c.RealIP()
		write_csv(uname, ip, csvname)
		returnHTML = ipss_html.HTMLvalidated()
	} else {
		returnHTML = ipss_html.HTMLfailed()
	}

	return returnHTML

}

func trivial_password(format string) string {
	var returnVar string
	switch format {
	case "dow":
		dow := time.Now().Weekday()
		returnVar = dow.String()[0:3]
	default:
		returnVar = "Invalid format"
	}
	return returnVar
}
func write_csv(uname_csv, ip_csv, csvname string) {
	ipData := [][]string{
		{uname_csv, ip_csv},
	}

	csvFile, err := os.Create(csvname)

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	defer csvFile.Close()

	csvwriter := csv.NewWriter(csvFile)

	for _, ipRow := range ipData {
		_ = csvwriter.Write(ipRow)
	}
	csvwriter.Flush()

}

func viper_path() {
	viper.SetConfigName("ipss_config")                   // name of config file (without extension)
	viper.AddConfigPath("$HOME/.config/ipss_self_serve") // path to config, call multiple times to add many search paths
	viper.AddConfigPath(".")                             // optionally look for config in the working directory
	err := viper.ReadInConfig()                          // Find and read the config file
	if err != nil {                                      // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error reading config file: %s \n", err))
	}
}
