// auth provides second-factor authentication implementations (TOTP, None).
package auth

import (
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
)

// SecondFactor defines the interface for second-factor authentication.
type SecondFactor interface {
	FormFields() string
	Validate(c echo.Context, username string, secrets map[string]string) (bool, error)
}

// NewSecondFactor returns a SecondFactor implementation based on the config value.
func NewSecondFactor(factorType string) (SecondFactor, error) {
	switch factorType {
	case "totp":
		return &TOTPFactor{}, nil
	case "none", "":
		return &NoneFactor{}, nil
	default:
		return nil, fmt.Errorf("unknown second_factor type: %q", factorType)
	}
}

// TOTPFactor validates a 6-digit TOTP code per RFC 6238.
type TOTPFactor struct{}

func (t *TOTPFactor) FormFields() string {
	return `<label for="totp_code">TOTP Code: </label><input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" /><br/>`
}

func (t *TOTPFactor) Validate(c echo.Context, username string, secrets map[string]string) (bool, error) {
	code := c.FormValue("totp_code")
	if code == "" {
		return false, nil
	}
	secret, ok := secrets[username]
	if !ok || secret == "" {
		return false, fmt.Errorf("no TOTP secret configured for user %q", username)
	}
	return totp.Validate(code, secret), nil
}

// NoneFactor always passes — used when only username+password is required.
type NoneFactor struct{}

func (n *NoneFactor) FormFields() string {
	return ""
}

func (n *NoneFactor) Validate(c echo.Context, username string, secrets map[string]string) (bool, error) {
	return true, nil
}
