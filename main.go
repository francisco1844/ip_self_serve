// IP Self Serve — captures authenticated users' IP addresses via a web form.
package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"ip_self_serve/auth"
	"ip_self_serve/handlers"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

//go:embed ipss_config.yaml.sample
var sampleConfig []byte

func main() {
	enrollUser := flag.String("enroll", "", "Generate TOTP secret for the given username")
	hashPassword := flag.String("hash-password", "", "Generate bcrypt hash for the given password")
	flag.Parse()

	if *hashPassword != "" {
		runHashPassword(*hashPassword)
		return
	}

	if *enrollUser != "" {
		runEnroll(*enrollUser)
		return
	}

	cfg := loadConfig()

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.Secure())
	e.Use(middleware.BodyLimit("1M"))

	e.GET("/", handlers.RootHandler(cfg))
	e.POST("/validate", handlers.ValidateHandler(cfg), handlers.IPRateLimit())

	e.Logger.Fatal(e.Start(":1180"))
}

func loadConfig() *handlers.AppConfig {
	viper.SetConfigName("ipss_config")
	viper.AddConfigPath("$HOME/.config/ipss_self_serve")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		bootstrapConfig()
		log.Fatalf("No config file found. A sample has been written to %s — edit it and restart.",
			configDir()+"/ipss_config.yaml")
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
	dir := configDir()
	dest := filepath.Join(dir, "ipss_config.yaml")

	if _, err := os.Stat(dest); err == nil {
		return // already exists
	}

	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("Warning: could not create config directory %s: %v", dir, err)
		return
	}

	if err := os.WriteFile(dest, sampleConfig, 0640); err != nil {
		log.Printf("Warning: could not write sample config to %s: %v", dest, err)
	}
}

func runHashPassword(password string) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to generate bcrypt hash: %v", err)
	}
	fmt.Println(string(hash))
}

func runEnroll(username string) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "IPSelfServe",
		AccountName: username,
	})
	if err != nil {
		log.Fatalf("Failed to generate TOTP key: %v", err)
	}

	fmt.Printf("TOTP enrollment for user: %s\n\n", username)
	fmt.Printf("Secret: %s\n\n", key.Secret())
	fmt.Printf("Provisioning URI (paste into authenticator app or generate QR code):\n%s\n\n", key.URL())
	fmt.Printf("Add to your ipss_config.yaml under the user entry:\n")
	fmt.Printf("  %s:\n    password: <bcrypt hash>\n    totp_secret: %s\n", username, key.Secret())
}
