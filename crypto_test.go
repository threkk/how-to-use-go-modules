package modexample

import "testing"
import "fmt"
import "math/rand"
import "time"

var gpg *GPGKey = &GPGKey{
	PubKeyPath:  "./public.gpg",
	PrivKeyPath: "./private.gpg",
	Pass:        "P@ssw0rd",
}

func getRandomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789"
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func TestGPKey(t *testing.T) {
	for i := 0; i < 10; i++ {
		msg := getRandomString(8)
		title := fmt.Sprintf("TestDecrypt %02d: Expecting %s", i, msg)
		t.Run(title, func(t *testing.T) {
			enc, err := gpg.Encrypt(msg)

			if err != nil {
				t.Error(err)
			}

			clear, err := gpg.Decrypt(enc)

			if err != nil {
				t.Error(err)
			}

			if err == nil && clear != msg {
				t.Errorf("wanted: %s", msg)
				t.Errorf("got: %s", clear)
			}
		})
	}
}
