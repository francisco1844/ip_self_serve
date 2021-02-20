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
	"golang.org/x/crypto/bcrypt"
)

var uname, ip string

func RootHandler(c echo.Context) error {
	return c.HTML(http.StatusOK, ipss_html.HTMLroot())

}

func ValidateHandler(c echo.Context) error {

	var ypass, ydynamic_password_format, returnHTML string

	form_name := c.FormValue("username")
	form_pass := c.FormValue("password")
	dynamic := c.FormValue("dynamic_password")

	viper_path()

	ypass = viper.GetString("users." + uname + ".password")
	ydynamic_password_format = viper.GetString("dynamic_password")
	computed_dynamic := dynamic_password(ydynamic_password_format)
	//	fmt.Println("Computed: ", computed_dynamic)
	//	fmt.Println("Submited: ", dynamic)
	if dynamic != computed_dynamic {
		returnHTML = ipss_html.HTMLfailed_dynamic()
	} else if ypass == "" {
		returnHTML = ipss_html.HTMLfailed()
	} else {
		returnHTML = validate_vars(ypass, form_pass, form_name, c)
	}

	return c.HTML(http.StatusOK, returnHTML)

}

func validate_vars(ypass, pass, name string, c echo.Context) string {
	var returnHTML string
	viper_path()
	csvname := viper.GetString("csv")

	if CheckPasswordHash(pass, ypass) {
		ip = c.RealIP()
		write_csv(uname, ip, csvname)
		returnHTML = ipss_html.HTMLvalidated()
	} else {
		returnHTML = ipss_html.HTMLfailed()
	}

	return returnHTML

}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func dynamic_password(format string) string {
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
