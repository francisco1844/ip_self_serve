// handlers implements HTTP handlers for IP Self Serve authentication and IP capture.
package handlers

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"ip_self_serve/auth"
	"ip_self_serve/ipss_html"

	"github.com/labstack/echo/v4"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"golang.org/x/crypto/bcrypt"
)

// AppConfig holds application configuration loaded once at startup.
type AppConfig struct {
	Users        map[string]UserConfig
	CSVPath      string
	SecondFactor auth.SecondFactor
	TOTPSecrets  map[string]string
}

// UserConfig holds per-user configuration.
type UserConfig struct {
	PasswordHash string
	TOTPSecret   string
}

var (
	csvMu         sync.Mutex
	validUsername  = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

func IPRateLimit() echo.MiddlewareFunc {
	rate := limiter.Rate{
		Period: 2 * time.Second,
		Limit:  1,
	}
	store := memory.NewStore()
	ipRateLimiter := limiter.New(store, rate)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			limiterCtx, err := ipRateLimiter.Get(c.Request().Context(), ip)
			if err != nil {
				log.Printf("IPRateLimit - ipRateLimiter.Get - err: %v, %s on %s", err, ip, c.Request().URL)
				return c.JSON(http.StatusInternalServerError, echo.Map{
					"success": false,
					"message": fmt.Sprintf("rate limiter error: %v", err),
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

			return next(c)
		}
	}
}

// RootHandler serves the login form with the configured second factor fields.
func RootHandler(cfg *AppConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		extraFields := cfg.SecondFactor.FormFields()
		return c.HTML(http.StatusOK, ipss_html.HTMLroot(extraFields))
	}
}

// ValidateHandler authenticates the user and captures their IP.
func ValidateHandler(cfg *AppConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		formName := c.FormValue("username")
		formPass := c.FormValue("password")

		if !validUsername.MatchString(formName) {
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}

		user, ok := cfg.Users[formName]
		if !ok || user.PasswordHash == "" {
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}

		// Validate second factor before password (fail fast on MFA)
		valid, err := cfg.SecondFactor.Validate(c, formName, cfg.TOTPSecrets)
		if err != nil {
			log.Printf("second factor error for user %q: %v", formName, err)
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}
		if !valid {
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}

		if !checkPasswordHash(formPass, user.PasswordHash) {
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}

		ip := c.RealIP()
		if err := writeCSV(formName, ip, cfg.CSVPath); err != nil {
			log.Printf("CSV write error: %v", err)
			return c.HTML(http.StatusInternalServerError, ipss_html.HTMLfailed())
		}

		return c.HTML(http.StatusOK, ipss_html.HTMLvalidated())
	}
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// sanitizeCSVField prevents CSV injection by prefixing dangerous characters.
func sanitizeCSVField(s string) string {
	if len(s) > 0 {
		switch s[0] {
		case '=', '+', '-', '@':
			return "'" + s
		}
	}
	return s
}

func writeCSV(username, ip, csvPath string) error {
	csvMu.Lock()
	defer csvMu.Unlock()

	f, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed opening CSV file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write([]string{
		sanitizeCSVField(strings.TrimSpace(username)),
		sanitizeCSVField(strings.TrimSpace(ip)),
	}); err != nil {
		return fmt.Errorf("failed writing CSV row: %w", err)
	}
	w.Flush()
	return w.Error()
}
