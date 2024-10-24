package otp_test

import (
	"crypto/sha512"
	"fmt"
	"log"

	"github.com/watsonserve/otp"
)

func ExampleGenSecret() {
	s, err := otp.GenSecret()
	if nil != err {
		log.Fatalln(err)
	}

	r := otp.GenAuthRule("label", "issuer", s, "SHA512")
	fmt.Println(r)
}

func ExampleGenTotp() {
	fmt.Println(otp.GenTotp(sha512.New, "EVGUUICK6MMMVPHSW4GTBBAETHDEPC5S"))
}
