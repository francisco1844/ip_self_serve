// IP Self Serve — captures authenticated users' IP addresses via a web form.
package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"image/png"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"ip_self_serve/auth"
	"ip_self_serve/handlers"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

//go:embed ipss_config.yaml.sample
var sampleConfig []byte

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -serve                Start the web server\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -serve -verbose       Start with request logging enabled\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -enroll <user>        Enroll a user (prompts for password)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -enroll <user> -totp  Enroll a user with TOTP setup\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nConfiguration:\n")
		fmt.Fprintf(os.Stderr, "  Config file ipss_config.yaml is searched in this order:\n")
		fmt.Fprintf(os.Stderr, "    1. $HOME/.config/ipss_self_serve/\n")
		fmt.Fprintf(os.Stderr, "    2. Current working directory (./)\n")
		fmt.Fprintf(os.Stderr, "  If no config is found, a sample is written to ./ipss_config.yaml\n")
	}

	enrollUser := flag.String("enroll", "", "enroll")
	withTOTP := flag.Bool("totp", false, "totp")
	serve := flag.Bool("serve", false, "serve")
	verbose := flag.Bool("verbose", false, "verbose")
	flag.Parse()

	if *withTOTP && *enrollUser == "" {
		log.Fatal("-totp can only be used with -enroll")
	}

	switch {
	case *enrollUser != "":
		runEnroll(*enrollUser, *withTOTP)
		return
	case *serve:
		// fall through to server startup with verbose flag
	default:
		flag.Usage()
		os.Exit(1)
	}

	cfg := loadConfig()

	e := echo.New()

	if !*verbose {
		e.HideBanner = true
		e.HidePort = true
	}

	// Configure IP extraction based on trusted proxies
	trustedProxies := viper.GetStringSlice("trusted_proxies")
	if len(trustedProxies) > 0 {
		var opts []echo.TrustOption
		for _, cidr := range trustedProxies {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Fatalf("Invalid trusted_proxies CIDR %q: %v", cidr, err)
			}
			opts = append(opts, echo.TrustIPRange(ipNet))
		}
		e.IPExtractor = echo.ExtractIPFromXFFHeader(opts...)
	} else {
		e.IPExtractor = echo.ExtractIPDirect()
	}
	e.Use(middleware.Recover())
	if *verbose {
		e.Use(middleware.Logger())
	}
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            31536000,
		ContentSecurityPolicy: "default-src 'self'; style-src 'self' 'unsafe-inline'",
	}))
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:    "form:csrf_token",
		CookieSameSite: http.SameSiteStrictMode,
		CookieHTTPOnly: true,
		CookieSecure:   true,
	}))
	e.Use(middleware.BodyLimit("1M"))

	e.GET("/", handlers.RootHandler(cfg), handlers.IPRateLimit())
	e.POST("/validate", handlers.ValidateHandler(cfg), handlers.IPRateLimit())

	e.Logger.Fatal(e.Start(":1180"))
}

func loadConfig() *handlers.AppConfig {
	viper.SetConfigName("ipss_config")
	viper.AddConfigPath(configDir())
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			bootstrapConfig()
			log.Fatalf("No config file found. A sample has been written to ./ipss_config.yaml — edit it and restart.")
		}
		log.Fatalf("Error reading config file: %v", err)
	}

	factorType := viper.GetString("auth.second_factor")
	sf, err := auth.NewSecondFactor(factorType)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	users := make(map[string]handlers.UserConfig)
	totpSecrets := make(map[string]string)

	userMap := viper.GetStringMap("users")
	for username := range userMap {
		pw := viper.GetString("users." + username + ".password")
		ts := viper.GetString("users." + username + ".totp_secret")
		users[username] = handlers.UserConfig{
			PasswordHash: pw,
			TOTPSecret:   ts,
		}
		if ts != "" {
			totpSecrets[username] = ts
		}
	}

	csvPath := viper.GetString("csv")
	if csvPath == "" {
		log.Fatal("Config error: 'csv' path is required")
	}

	return &handlers.AppConfig{
		Users:        users,
		CSVPath:      csvPath,
		SecondFactor: sf,
		TOTPSecrets:  totpSecrets,
	}
}

func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Cannot determine home directory: %v", err)
	}
	return filepath.Join(home, ".config", "ipss_self_serve")
}

func bootstrapConfig() {
	dest := "ipss_config.yaml"

	if _, err := os.Stat(dest); err == nil {
		return // already exists
	}

	if err := os.WriteFile(dest, sampleConfig, 0600); err != nil {
		log.Printf("Warning: could not write sample config to %s: %v", dest, err)
	}
}

// PasswordPolicy holds configurable password complexity rules.
type PasswordPolicy struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireNumber bool
	RequireSymbol bool
}

func loadPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:     viper.GetInt("password_policy.min_length"),
		RequireUpper:  viper.GetBool("password_policy.require_upper"),
		RequireLower:  viper.GetBool("password_policy.require_lower"),
		RequireNumber: viper.GetBool("password_policy.require_number"),
		RequireSymbol: viper.GetBool("password_policy.require_symbol"),
	}
}

func validatePassword(password string, policy PasswordPolicy) error {
	minLen := policy.MinLength
	if minLen == 0 {
		minLen = 8
	}
	if len(password) < minLen {
		return fmt.Errorf("password must be at least %d characters", minLen)
	}

	var hasUpper, hasLower, hasNumber, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}

	var missing []string
	if policy.RequireUpper && !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if policy.RequireLower && !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if policy.RequireNumber && !hasNumber {
		missing = append(missing, "number")
	}
	if policy.RequireSymbol && !hasSymbol {
		missing = append(missing, "symbol")
	}
	if len(missing) > 0 {
		return fmt.Errorf("password must contain: %s", strings.Join(missing, ", "))
	}
	return nil
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		return string(pw)
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		log.Fatal("Failed to read password from stdin")
	}
	return strings.TrimRight(scanner.Text(), "\r\n")
}

func runEnroll(username string, withTOTP bool) {
	// Load config for password policy; missing config is fine (use defaults).
	viper.SetConfigName("ipss_config")
	viper.AddConfigPath(configDir())
	viper.AddConfigPath(".")
	_ = viper.ReadInConfig()

	policy := loadPasswordPolicy()

	password := readPassword("Enter password: ")
	confirm := readPassword("Confirm password: ")
	if password != confirm {
		log.Fatal("Passwords do not match")
	}
	if password == "" {
		log.Fatal("Password cannot be empty")
	}
	if err := validatePassword(password, policy); err != nil {
		log.Fatalf("Password rejected: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 13)
	if err != nil {
		log.Fatalf("Failed to generate bcrypt hash: %v", err)
	}

	fmt.Printf("\nAdd to your ipss_config.yaml under users:\n\n")
	fmt.Printf("  %s:\n", username)
	fmt.Printf("    password: %s\n", string(hash))

	if withTOTP {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "IPSelfServe",
			AccountName: username,
		})
		if err != nil {
			log.Fatalf("Failed to generate TOTP key: %v", err)
		}
		fmt.Printf("    totp_secret: %s\n", key.Secret())
		fmt.Printf("\nTOTP Secret: %s\n", key.Secret())

		qrFile := fmt.Sprintf("%s_totp_qr.png", username)
		img, err := key.Image(256, 256)
		if err != nil {
			log.Fatalf("Failed to generate QR code: %v", err)
		}
		f, err := os.Create(qrFile)
		if err != nil {
			log.Fatalf("Failed to create QR image file: %v", err)
		}
		if err := png.Encode(f, img); err != nil {
			f.Close()
			log.Fatalf("Failed to write QR image: %v", err)
		}
		f.Close()
		fmt.Printf("QR code saved to: %s (scan with authenticator app)\n", qrFile)
	}
}
