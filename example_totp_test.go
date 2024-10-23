package totp_test

import (
	"crypto/sha512"
	"fmt"
	"log"

	"github.com/watsonserve/totp"
)

func ExampleGenSecret() {
	s, err := totp.GenSecret()
	if nil != err {
		log.Fatalln(err)
	}

	r := totp.GenAuthRule("label", "issuer", s, "SHA512")
	fmt.Println(r)
}

func ExampleGenTotp() {
	fmt.Println(totp.GenTotp("EVGUUICK6MMMVPHSW4GTBBAETHDEPC5S", sha512.New))
}
