
package crypto

import (
	// "fmt"
	"crypto/rand"
	"testing"
	"github.com/dedis/crypto/edwards/ed25519"

)

func TestPartialBlindSignatureScheme(t *testing.T) {


    // I tried suite := ed25519.NewAES128SHA256Ed25519(true) but got null pointer derefs
    suite :=  ed25519.NewAES128SHA256Ed25519(true)

	privKey, _ := SchnorrGenerateKeypair(suite)
	pubKey := SchnorrExtractPubkey(privKey)

	// now "agree" some information. For our purposes just fish 
	// some bytes out of /dev/urandom

	info := make([]byte, 16)
	_, err := rand.Read(info)
    if err != nil {
        t.Error(err.Error())
    }

   	badinfo := make([]byte, 16)
	_, err = rand.Read(info)
    if err != nil {
        t.Error(err.Error())
    }


    // likewise let's sign a random message.
    message := make([]byte, 16)
	_, err = rand.Read(message)
    if err != nil {
        t.Error(err.Error())
    }

	// now the first step from pg277

	signerParams, err := NewPrivateParams(suite, info)
	if err != nil {
		t.Error(err.Error())
	}

	// "send" these to the user.
	userPublicParams := signerParams.DerivePubParams()


	// now the user does their thing.
	challenge, userPrivateParams, err := ClientGenerateChallenge(suite, userPublicParams, pubKey, info, message)
	if err != nil {
		t.Error(err.Error())
	}

	// and now we compute a response on the server side.
	response := ServerGenerateResponse(suite, challenge, signerParams, privKey)

	// finally, we can sign the message and check it verifies.
	sig, worked := ClientSignBlindly(suite, userPrivateParams, response, pubKey, message)

	//fmt.Println(blindSignature)

	if worked != true {
		t.Error("Signature scheme did not return true.")
	}


	// now verify this worked fine.
	result, err := VerifyBlindSignature(suite, pubKey, sig, info, message)

	if err != nil {
		t.Error(err.Error())
	}
	if result != true {
		t.Error("VerifyBlindSignature failed with valid info - this should work.")
	}

	// and now try again with the wrong information to prove
	// that any change in this information fails to generate the correct
	// signature.
	result, err = VerifyBlindSignature(suite, pubKey, sig, badinfo, message)

	if err != nil {
		t.Error(err.Error())
	}
	if result != false {
		t.Error("VerifyBlindSignature succeeded with bad info - this should fail.")
	}
}
