package handlers

import (
	"fmt"
	"ip_self_serve/ipss_html"
	"net/http"
	"strconv"

	"encoding/csv"
	"log"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

var uname, ip string

var (
	ipRateLimiter *limiter.Limiter
	store         limiter.Store
)

func IPRateLimit() echo.MiddlewareFunc {
	// 1. Configure
	rate := limiter.Rate{
		Period: 2 * time.Second,
		Limit:  1,
	}
	store = memory.NewStore()
	ipRateLimiter = limiter.New(store, rate)

	// 2. Return middleware handler
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			ip := c.RealIP()
			limiterCtx, err := ipRateLimiter.Get(c.Request().Context(), ip)
			if err != nil {
				log.Printf("IPRateLimit - ipRateLimiter.Get - err: %v, %s on %s", err, ip, c.Request().URL)
				return c.JSON(http.StatusInternalServerError, echo.Map{
					"success": false,
					"message": err,
				})
			}

			h := c.Response().Header()
			h.Set("X-RateLimit-Limit", strconv.FormatInt(limiterCtx.Limit, 10))
			h.Set("X-RateLimit-Remaining", strconv.FormatInt(limiterCtx.Remaining, 10))
			h.Set("X-RateLimit-Reset", strconv.FormatInt(limiterCtx.Reset, 10))

			if limiterCtx.Reached {
				log.Printf("Too Many Requests from %s on %s", ip, c.Request().URL)
				return c.JSON(http.StatusTooManyRequests, echo.Map{
					"success": false,
					"message": "Too Many Requests on " + c.Request().URL.String(),
				})
			}

			// log.Printf("%s request continue", c.RealIP())
			return next(c)
		}
	}
}

func RootHandler(c echo.Context) error {
	return c.HTML(http.StatusOK, ipss_html.HTMLroot())

}

func ValidateHandler(c echo.Context) error {

	var ypass, ydynamic_password_format, returnHTML string

	form_name := c.FormValue("username")
	form_pass := c.FormValue("password")
	dynamic := c.FormValue("dynamic_password")

	viper_path()
	ypass = viper.GetString("users." + form_name + ".password")
	// fmt.Println("Form user:", form_name, " - Yaml password (if user matched):", ypass)
	ydynamic_password_format = viper.GetString("dynamic_password")
	computed_dynamic := dynamic_password(ydynamic_password_format)
	//	fmt.Println("Computed: ", computed_dynamic)
	//	fmt.Println("Submited: ", dynamic)
	if dynamic != computed_dynamic {
		returnHTML = ipss_html.HTMLfailed_dynamic()
	} else if ypass == "" {
		returnHTML = ipss_html.HTMLfailed()
	} else {
		returnHTML = validate_vars(form_name, ypass, form_pass, form_name, c)
	}

	return c.HTML(http.StatusOK, returnHTML)

}

func validate_vars(user, ypass, pass, name string, c echo.Context) string {
	var returnHTML string
	viper_path()
	csvname := viper.GetString("csv")

	if CheckPasswordHash(pass, ypass) {
		ip = c.RealIP()
		write_csv(user, ip, csvname)
		returnHTML = ipss_html.HTMLvalidated()
	} else {
		// fmt.Println("Hash match hfailed")
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
