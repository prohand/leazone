package auth

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"image/png"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const totpPeriod = 30

var totpOpts = totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// TOTPSetup is a freshly generated secret, shown once to the user.
type TOTPSetup struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauthUrl"`
	QRPNG      string `json:"qrPng"`
}

// NewTOTP generates a secret for account name on issuer.
func NewTOTP(issuer, account string) (TOTPSetup, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account, SecretSize: 20,
		Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return TOTPSetup{}, err
	}
	img, err := key.Image(240, 240)
	if err != nil {
		return TOTPSetup{}, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return TOTPSetup{}, err
	}
	return TOTPSetup{
		Secret:     key.Secret(),
		OtpauthURL: key.URL(),
		QRPNG:      "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// CheckTOTP verifies code at time now with ±1 step tolerance. It returns the
// matched time-step counter, which must be strictly greater than the last
// accepted counter to block replays. ok is false when the code is wrong.
func CheckTOTP(secret, code string, now time.Time, lastCounter int64) (counter int64, ok bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	base := now.Unix() / totpPeriod
	for _, d := range []int64{0, -1, 1} {
		c := base + d
		if c <= lastCounter {
			continue
		}
		want, err := totp.GenerateCodeCustom(secret, time.Unix(c*totpPeriod, 0), totpOpts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}
