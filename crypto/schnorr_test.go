
package crypto

// These are the unit tests for
// the crypto package. I have tested
// keyset generation, signing and verification only

import (
    "github.com/dedis/crypto/edwards/ed25519"
    "testing"
)

func TestSchnorrGenerateKeyset(t *testing.T) {
    
    // again, if I had more time and was publishing 
    // this, I'd be calculating some known values 
    // outside this code
    // and checking generation produced what it 
    // should.
    suite := ed25519.NewAES128SHA256Ed25519(true) 
    _, err := SchnorrGenerateKeypair(suite)
    if err != nil {
        t.Error("Keypair generation failed")
    }
}

func TestSchnorrSignature(t *testing.T) {
    
    suite := ed25519.NewAES128SHA256Ed25519(true) 
    
    // for good measure, do a few.
    // in proper code we'd not just rely 
    // on random generation, we'd also have
    // some known test vectors.
    for i := 0; i < 100; i++ {
        kv, err := SchnorrGenerateKeypair(suite)
        if err != nil {
            t.Error("Keypair generation failed")
        }
        
        pk := SchnorrExtractPubkey(kv) 
        message := []byte("This is a test")
        wrongmessage := []byte("Clearly this shouldn't work")
        

        sig, err := SchnorrSign(suite, kv, message)
        if err != nil {
            t.Error("Signature Generation failed")    }


        v1, e1 := SchnorrVerify(suite, pk, message, sig)
        if e1 != nil {
            t.Error("Error during Verification")
        }
        if v1 == false {
            t.Error("Verification of signature failed")
        }

        v2, e2 := SchnorrVerify(suite, pk, wrongmessage, sig)
        if e2 != nil {
            t.Error("Error during Verification")
        }
        if v2 == true {
            t.Error("Verification of signature succeeded for bad message")
        }
    }
}


func TestLoadSaveKeys(t *testing.T) {
    
    suite := ed25519.NewAES128SHA256Ed25519(true) 
    
    keypair, err := SchnorrGenerateKeypair(suite)
    if err != nil {
        t.Error("Keypair generation failed")
    }
        
    pk := SchnorrExtractPubkey(keypair)


    err = SchnorrSaveKeypair("/tmp/gotests.pri", suite, keypair)
    if err !=  nil { t.Error("Failed to write file") }
    err = SchnorrSavePubkey("/tmp/gotests.pub", suite, pk)
    if err !=  nil { t.Error("Failed to write file") }

    keypair_loaded, err := SchnorrLoadKeypair("/tmp/gotests.pri", suite)
    if err !=  nil { t.Error("Failed to load keypair") }
    pk_loaded, err := SchnorrLoadPubkey("/tmp/gotests.pub", suite)
    
    message := []byte("This is a test")
    wrongmessage := []byte("Clearly this shouldn't work")
        
    sig, err := SchnorrSign(suite, keypair_loaded, message)
    if err != nil {
        t.Error("Signature Generation failed")    }


    v1, e1 := SchnorrVerify(suite, pk_loaded, message, sig)
    if e1 != nil {
        t.Error("Error during Verification")
    }
    if v1 == false {
        t.Error("Verification of signature failed")
    }

    v2, e2 := SchnorrVerify(suite, pk_loaded, wrongmessage, sig)
    if e2 != nil {
        t.Error("Error during Verification")
    }
    if v2 == true {
        t.Error("Verification of signature succeeded for bad message")
    }
    
}