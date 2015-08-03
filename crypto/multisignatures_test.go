
package crypto

import (
	"bytes"
	"fmt"
	"crypto/rand"
	"github.com/dedis/crypto/abstract"
    "github.com/dedis/crypto/edwards/ed25519"
    "testing"
)
// This test function runs through a 2-party 
// Schnorr Multi-Signature Scheme as described in the notes.
// This code is my TDD-code to validate the crypto 
// before using it in the network stack properly
// The code file is commented with the relevant steps.
func TestMultisignature2ServerScenario(t *testing.T) {

	suite := ed25519.NewAES128SHA256Ed25519(true) 

	// Generate ourselves two keypairs, one for each "server"
	kv_1, err := SchnorrGenerateKeypair(suite)
	if err != nil { t.Error(err.Error()) }
	kv_2, err := SchnorrGenerateKeypair(suite)
	if err != nil { t.Error(err.Error()) }

	// Make a random message and "send" it to the server
	randomdata := make([]byte, 1024)
    _, err = rand.Read(randomdata)
    if err != nil {
        fmt.Println(err.Error())
    	return
    }

    // client side
    // compute the shared public key given the public keys of each 
    // participant.

    pks := []SchnorrPublicKey {SchnorrExtractPubkey(kv_1), SchnorrExtractPubkey(kv_2)}
    sharedpubkey := SchnorrMComputeSharedPublicKey(suite, pks)

    // SERVER
    // In response to this each server will generate two
    // arbitrary secrets and respond with a commitment.
    commit1, err := SchnorrMGenerateCommitment(suite)
    if err != nil { 
    	t.Error(err.Error()) 
    }

    commit2, err := SchnorrMGenerateCommitment(suite)
    if err != nil { 
    	t.Error(err.Error()) 
    }

    // Client side
    commit_array := []SchnorrMPublicCommitment{SchnorrMPublicCommitment{commit1.PublicCommitment().T}, SchnorrMPublicCommitment{commit2.PublicCommitment().T}}
    aggregate_commitment := SchnorrMComputeAggregateCommitment(suite, commit_array)

    // client and servers
    collective_challenge := SchnorrMComputeCollectiveChallenge(suite, randomdata, aggregate_commitment)
  	
    // servers respond to client with responses
  	response_1 := SchnorrMUnmarshallCCComputeResponse(suite, kv_1, commit1, collective_challenge)
  	response_2 := SchnorrMUnmarshallCCComputeResponse(suite, kv_2, commit2, collective_challenge)

  	// finally, we compute a signature given the responses.
  	responsearr := []SchnorrMResponse{ response_1, response_2 }

  	sig := SchnorrMComputeSignatureFromResponses(suite, collective_challenge, responsearr)

  	// After all that, we should be able to validate the signature
  	// against the group public key. First we serialize the signature

  	buf := bytes.Buffer{} 
    abstract.Write(&buf, &sig, suite)
    bsig := buf.Bytes()

	verified, err := SchnorrVerify(suite, sharedpubkey.GetSchnorrPK(), randomdata, bsig)
    if err != nil {
        t.Error("Error during Verification")
    }
    if verified == false {
        t.Error("Verification of signature failed.")
    }
}





func TestMultisignature5ServerScenario(t *testing.T) {

    suite := ed25519.NewAES128SHA256Ed25519(true) 

    // Generate ourselves two keypairs, one for each "server"
    kv_1, err := SchnorrGenerateKeypair(suite)
    if err != nil { t.Error(err.Error()) }
    kv_2, err := SchnorrGenerateKeypair(suite)
    if err != nil { t.Error(err.Error()) }
    kv_3, err := SchnorrGenerateKeypair(suite)
    if err != nil { t.Error(err.Error()) }
    kv_4, err := SchnorrGenerateKeypair(suite)
    if err != nil { t.Error(err.Error()) }
    kv_5, err := SchnorrGenerateKeypair(suite)
    if err != nil { t.Error(err.Error()) }

    // Make a random message and "send" it to the server
    randomdata := make([]byte, 1024)
    _, err = rand.Read(randomdata)
    if err != nil {
        fmt.Println(err.Error())
        return
    }

    // client side
    // compute the shared public key given the public keys of each 
    // participant.

    pks := []SchnorrPublicKey {SchnorrExtractPubkey(kv_1), 
                               SchnorrExtractPubkey(kv_2),
                               SchnorrExtractPubkey(kv_3),
                               SchnorrExtractPubkey(kv_4),
                               SchnorrExtractPubkey(kv_5)}
    sharedpubkey := SchnorrMComputeSharedPublicKey(suite, pks)

    // SERVER
    // In response to this each server will generate two
    // arbitrary secrets and respond with a commitment.
    commit1, err := SchnorrMGenerateCommitment(suite)
    if err != nil { 
        t.Error(err.Error()) 
    }

    commit2, err := SchnorrMGenerateCommitment(suite)
    if err != nil { 
        t.Error(err.Error()) 
    }
    commit3, err := SchnorrMGenerateCommitment(suite)
    if err != nil { 
        t.Error(err.Error()) 
    }
    commit4, err := SchnorrMGenerateCommitment(suite)
    if err != nil { 
        t.Error(err.Error()) 
    }
    commit5, err := SchnorrMGenerateCommitment(suite)
    if err != nil { 
        t.Error(err.Error()) 
    }

    // Client side
    commit_array := []SchnorrMPublicCommitment{SchnorrMPublicCommitment{commit1.PublicCommitment().T}, 
                                               SchnorrMPublicCommitment{commit2.PublicCommitment().T},
                                               SchnorrMPublicCommitment{commit3.PublicCommitment().T},
                                               SchnorrMPublicCommitment{commit4.PublicCommitment().T},
                                               SchnorrMPublicCommitment{commit5.PublicCommitment().T}}
    aggregate_commitment := SchnorrMComputeAggregateCommitment(suite, commit_array)

    // client and servers
    collective_challenge := SchnorrMComputeCollectiveChallenge(suite, randomdata, aggregate_commitment)
    
    // servers respond to client with responses
    response_1 := SchnorrMUnmarshallCCComputeResponse(suite, kv_1, commit1, collective_challenge)
    response_2 := SchnorrMUnmarshallCCComputeResponse(suite, kv_2, commit2, collective_challenge)
    response_3 := SchnorrMUnmarshallCCComputeResponse(suite, kv_3, commit3, collective_challenge)
    response_4 := SchnorrMUnmarshallCCComputeResponse(suite, kv_4, commit4, collective_challenge)
    response_5 := SchnorrMUnmarshallCCComputeResponse(suite, kv_5, commit5, collective_challenge)

    // finally, we compute a signature given the responses.
    responsearr := []SchnorrMResponse{ response_1, response_2, response_3, response_4, response_5 }

    sig := SchnorrMComputeSignatureFromResponses(suite, collective_challenge, responsearr)

    // After all that, we should be able to validate the signature
    // against the group public key. First we serialize the signature

    buf := bytes.Buffer{} 
    abstract.Write(&buf, &sig, suite)
    bsig := buf.Bytes()

    verified, err := SchnorrVerify(suite, sharedpubkey.GetSchnorrPK(), randomdata, bsig)
    if err != nil {
        t.Error("Error during Verification")
    }
    if verified == false {
        t.Error("Verification of signature failed.")
    }
}

