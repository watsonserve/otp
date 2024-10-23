package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"hash"
	"time"
)

const PERIOD = 30 // 30s
const DIGITS = 6  // %06d

func GenSecret() (string, error) {
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if nil != err {
		return "", err
	}

	strSecret := base32.StdEncoding.EncodeToString(secret)
	return strSecret, nil
}

func int64Mem(num int64) []byte {
	bytes := make([]byte, 8)

	for i := 7; i >= 0; i-- {
		bytes[i] = byte(num & 0xff)
		num = num >> 8
	}

	return bytes
}

func GenAuthRule(label, issuer, secret, algorithm string, periodDigits ...int) string {
	period := PERIOD // 30s
	digits := DIGITS // %06d
	numLen := len(periodDigits)
	if 0 < numLen {
		period = periodDigits[0]
	}
	if 1 < numLen {
		digits = periodDigits[1]
	}

	return fmt.Sprintf(
		"otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d\n",
		label, secret, issuer, algorithm, digits, period)
}

func GenTotp(secret string, algorithm func() hash.Hash, periodDigits ...int) (string, error) {
	period := PERIOD // 30s
	digits := DIGITS // %06d
	numLen := len(periodDigits)
	if 0 < numLen {
		period = periodDigits[0]
	}
	if 1 < numLen {
		digits = periodDigits[1]
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if nil != err {
		return "", err
	}

	t := time.Now().Unix() / int64(period)
	encoder := hmac.New(algorithm, key)
	_, err = encoder.Write(int64Mem(t))
	if nil != err {
		return "", err
	}

	hash := encoder.Sum(nil)
	// get offset
	offset := int(hash[len(hash)-1] & 0xf)
	n := (uint(hash[offset]&0x7f) << 24) | (uint(hash[offset+1]) << 16) | (uint(hash[offset+2]) << 8) | (uint(hash[offset+3]&0xff) << 0)

	format := fmt.Sprintf("%%0%dd", digits)
	code := fmt.Sprintf(format, n)
	rawLen := len(code)
	if digits < rawLen {
		code = code[rawLen-digits:]
	}
	return code, nil
}
