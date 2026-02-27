// handlers implements HTTP handlers for IP Self Serve authentication and IP capture.
package handlers

import (
	"encoding/csv"
	"fmt"
	"log"
	"net"
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
	DefaultIP    string // "connection" (default) or "external"
}

// UserConfig holds per-user configuration.
type UserConfig struct {
	PasswordHash string
	TOTPSecret   string
}

var (
	csvMu         sync.Mutex
	validUsername  = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	authThrottle  = newAccountThrottle(5, 5*time.Minute)
	// dummyHash is used for constant-time responses when a username doesn't exist.
	dummyHash     []byte
)

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy-placeholder"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("failed to generate dummy bcrypt hash: %v", err)
	}
	dummyHash = h
}

// accountThrottle tracks per-username failed auth attempts.
type accountThrottle struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	limit    int
	window   time.Duration
}

func newAccountThrottle(limit int, window time.Duration) *accountThrottle {
	return &accountThrottle{
		failures: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// isLimited returns true if the username has exceeded the failure limit within the window.
func (a *accountThrottle) isLimited(username string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := time.Now().Add(-a.window)
	times := a.failures[username]

	// Prune expired entries
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	a.failures[username] = valid

	return len(valid) >= a.limit
}

// recordFailure records a failed auth attempt for the username.
func (a *accountThrottle) recordFailure(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures[username] = append(a.failures[username], time.Now())
}

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
					"message": "internal server error",
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
	defaultIP := cfg.DefaultIP
	if defaultIP != "external" {
		defaultIP = "connection"
	}
	return func(c echo.Context) error {
		extraFields := cfg.SecondFactor.FormFields()
		csrfToken, _ := c.Get("csrf").(string)
		return c.HTML(http.StatusOK, ipss_html.HTMLroot(extraFields, csrfToken, c.RealIP(), defaultIP))
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
			// Run bcrypt against dummy hash to prevent username enumeration via timing.
			bcrypt.CompareHashAndPassword(dummyHash, []byte(formPass))
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}

		if authThrottle.isLimited(formName) {
			log.Printf("account throttled for user %q from %s", formName, c.RealIP())
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}

		// Validate second factor before password (fail fast on MFA)
		valid, err := cfg.SecondFactor.Validate(c, formName, cfg.TOTPSecrets)
		if err != nil {
			log.Printf("second factor error for user %q: %v", formName, err)
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}
		if !valid {
			authThrottle.recordFailure(formName)
			log.Printf("second factor validation failed for user %q from %s", formName, c.RealIP())
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}

		if !checkPasswordHash(formPass, user.PasswordHash) {
			authThrottle.recordFailure(formName)
			return c.HTML(http.StatusUnauthorized, ipss_html.HTMLfailed())
		}

		comment := c.FormValue("comment")
		if strings.Contains(comment, ",") {
			return c.HTML(http.StatusBadRequest, ipss_html.HTMLinvalidComment())
		}

		connectionIP := c.RealIP()
		ip := connectionIP
		if selectedIP := c.FormValue("selected_ip"); selectedIP != "" {
			if net.ParseIP(selectedIP) != nil {
				ip = selectedIP
			} else {
				log.Printf("invalid selected_ip %q from %s, falling back to connection IP", selectedIP, connectionIP)
			}
		}
		if ip != connectionIP {
			log.Printf("user %q submitted external IP %s (connection IP: %s)", formName, ip, connectionIP)
		}
		if err := writeCSV(formName, comment, ip, cfg.CSVPath); err != nil {
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
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 0 {
		switch s[0] {
		case '=', '+', '-', '@':
			return "'" + s
		}
	}
	return s
}

func writeCSV(username, comment, ip, csvPath string) error {
	csvMu.Lock()
	defer csvMu.Unlock()

	f, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed opening CSV file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat CSV file: %w", err)
	}
	if info.Mode().Perm()&^os.FileMode(0600) != 0 {
		if err := f.Chmod(0600); err != nil {
			return fmt.Errorf("failed to chmod CSV file: %w", err)
		}
	}

	w := csv.NewWriter(f)
	if err := w.Write([]string{
		sanitizeCSVField(strings.TrimSpace(username)),
		sanitizeCSVField(strings.TrimSpace(comment)),
		sanitizeCSVField(strings.TrimSpace(ip)),
	}); err != nil {
		return fmt.Errorf("failed writing CSV row: %w", err)
	}
	w.Flush()
	return w.Error()
}
