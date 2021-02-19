package main
import (
        "fmt"
        "github.com/labstack/echo/v4"
        "github.com/spf13/viper"
        "net/http"
)

var trivial_password string

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

        // Static folders
        e.Static("/css", "css")



        // Route => handler
//        e.GET("/", func(c echo.Context) error {
//                return c.HTML(http.StatusOK, "Hello, World!\n")
//        })

	e.GET("/", RouteHandler)

        // Start server
        e.Logger.Fatal(e.Start(":1323"))
}

func RouteHandler(c echo.Context) error {
	uname := c.FormValue("username")
	pass := c.FormValue("password")
	hash := c.FormValue("hash")
	if uname != "" {
		if pass == trivial_password {
			ip := c.RealIP()
			return c.HTML(http.StatusOK, LoginHTML + ip + hash)
		} else {
			fmt.Println("Simple password did not match")
		}
	} else {
		fmt.Println("Username cannot be blank")
	}
	return c.HTML(http.StatusOK, LoginHTML)
}
