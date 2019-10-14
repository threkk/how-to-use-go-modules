package modexample

import (
	"io/ioutil"

	"github.com/ProtonMail/gopenpgp/helper"
)

type GPGKey struct {
	PubKeyPath  string
	PrivKeyPath string
	pubKey      string
	privKey     string
	Pass        string
}

func (gpg *GPGKey) Encrypt(msg string) (string, error) {
	if gpg.pubKey == "" {
		buff, err := ioutil.ReadFile(gpg.PubKeyPath)
		if err != nil {
			return "", err
		}
		gpg.pubKey = string(buff)
	}
	return helper.EncryptMessageArmored(gpg.pubKey, msg)
}

func (gpg *GPGKey) Decrypt(msg string) (string, error) {
	if gpg.privKey == "" {
		buff, err := ioutil.ReadFile(gpg.PrivKeyPath)
		if err != nil {
			return "", err
		}

		gpg.privKey = string(buff)
	}
	return helper.DecryptMessageArmored(gpg.privKey, gpg.Pass, msg)
}
