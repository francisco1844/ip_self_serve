package main
import (
        "fmt"
        "github.com/labstack/echo/v4"
        "github.com/spf13/viper"
        "net/http"
)

var trivial_password, Pass string

func main() {
//var trivial_password string

       viper.SetConfigName("ipss_config")         // name of config file (without extension)
        viper.AddConfigPath("$HOME/")             // path to config, call multiple times to add many search paths
        viper.AddConfigPath(".")                  // optionally look for config in the working directory
        err := viper.ReadInConfig()               // Find and read the config file
        if err != nil {                           // Handle errors reading the config file
                panic(fmt.Errorf("Fatal error reading config file: %s \n", err))
        }
        trivial_password = viper.Get("trivial_password").(string)

        // Echo instance
        e := echo.New()

        e.GET("/", rootHandler)
        e.GET("/matchPass", simpleMatch)
        // Start server
        e.Logger.Fatal(e.Start(":1323"))
}

func rootHandler(c echo.Context) error {
	uname := c.FormValue("username")
	Pass = c.FormValue("password")
//	hash := c.FormValue("hash")
	if uname != "" {
      simpleMatch(c)
	} else {
			return c.HTML(http.StatusOK, LoginHTML + "Username cannot be blank")
	}
	return c.HTML(http.StatusOK, LoginHTML)
}

func simpleMatch(c echo.Context) error {
  if Pass == trivial_password {
    ip := c.RealIP()
    return c.HTML(http.StatusOK, "<br> The IP Address is " + ip)
  } else {
    return c.HTML(http.StatusOK, "<br>" + "The simple password did not match")
  }
  return c.HTML(http.StatusOK, LoginHTML+ "Did not check password, this shouldn't happen")
}
