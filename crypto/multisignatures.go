
package crypto

/* This file implements Schnorr-multi signatures 
   based on the schnorr.go file of this library.

    
*/

import (
    "crypto/rand"
    "golang.org/x/crypto/sha3"
    "github.com/dedis/crypto/abstract"
)


// This is our internal tracking structure 
// for subscriptions to the 
// multiparty scheme. Everyone joins by being 
// added here; we are ready to finalize we'll
// generate a SchnorrMultiSignaturePublicKey
type schnorrMState struct {
	Keysets   [] SchnorrKeyset
	O         abstract.Point  
	n         int
}

// This is the group public key.
// Conveniently it holds all the individual
// public keys 
type SchnorrMultiSignaturePublicKey struct {
	P         abstract.Point
}


// This structure holds T = g^v for
// group G. Don't send this to your clients -
// send .T only :)
type SchnorrMPrivateCommitment struct {
	V         abstract.Secret
	T         abstract.Point
}

// Represents a public commitment made by one party
type SchnorrMPublicCommitment struct {
    T         abstract.Point
}


func (this * SchnorrMPrivateCommitment) PublicCommitment () SchnorrMPublicCommitment {
    return SchnorrMPublicCommitment{this.T}
}

func (this * SchnorrMultiSignaturePublicKey) GetSchnorrPK () SchnorrPublicKey {
    return SchnorrPublicKey{this.P}
}

type SchnorrMAggregateCommmitment struct {
    P         abstract.Point
}

type SchnorrMResponse struct { 
    R         abstract.Secret
}

func SchnorrMGenerateCommitment (suite abstract.Suite) (SchnorrMPrivateCommitment, error){
	rsource := make([]byte, 16)
    _, err := rand.Read(rsource)
    if err != nil {
        return SchnorrMPrivateCommitment{}, err
    }
    // I have no idea if I just encrypted randomness or not
    // I'm hoping this just reads the state out.
    rct := suite.Cipher(rsource)
    
    v := suite.Secret().Pick(rct)           // some v
    t := suite.Point().Mul(nil, v)          // g^v = t
    return SchnorrMPrivateCommitment{T: t, V:v}, nil
}


// (Either side) This function computes the shared public key 
// by adding public key points over the curve group.
// Since each public key is already g*k where g is the group 
// generator this is all we need to do
func SchnorrMComputeSharedPublicKey(suite abstract.Suite,
                                    pkeys[] SchnorrPublicKey) SchnorrMultiSignaturePublicKey {
    
    var P abstract.Point = pkeys[0].Y

    for _, pkey := range pkeys[1:] {
        P.Add(P, pkey.Y)
    }
    return SchnorrMultiSignaturePublicKey{P}
}

// (Client side) The client requiring the n-signature scheme
// performs the addition of points under the elliptic curve group
// and returns the aggregate commitment as a raw point 
// in bytes for transmission to the server
func SchnorrMComputeAggregateCommitment(suite abstract.Suite,
                                    pcommits[] SchnorrMPublicCommitment) SchnorrMAggregateCommmitment {
    var P abstract.Point = pcommits[0].T

    for _, pcommit := range pcommits[1:] {
        P.Add(P, pcommit.T)
    }
    k := SchnorrMAggregateCommmitment{P}
    return k

    /*buf := bytes.Buffer{} 
    abstract.Write(&buf, &k, suite)
    return buf.Bytes()*/
}


// (Either side) This function takes the aggregate public commitment 
// r and returns sha3(m||r) for a given message. 
func SchnorrMComputeCollectiveChallenge(suite abstract.Suite,
                                        msg[] byte,
                                        pubCommit SchnorrMAggregateCommmitment) []byte {

    p_bin, _ := pubCommit.P.MarshalBinary()
    msg_and_p := append(msg, p_bin...) 
    hasher := sha3.New256()
    hasher.Write(msg_and_p)
    h := hasher.Sum(nil)
    return h
}


// (Server side) This function reads the collective challenge 
// from the wire, generates and serializes a response 
// to that as a raw "secret"
func SchnorrMUnmarshallCCComputeResponse (suite abstract.Suite,
                                          kv SchnorrKeyset,
                                          privatecommit SchnorrMPrivateCommitment, 
                                          cc []byte) SchnorrMResponse {
    hct := suite.Cipher(cc)
    c := suite.Secret().Pick(hct)
    r := suite.Secret()
    r.Mul(c, kv.X).Sub(privatecommit.V, r)

    return SchnorrMResponse{r}
}

// this function produces a signature given a response from the server.
func SchnorrMComputeSignatureFromResponses(suite abstract.Suite,
                                           cc []byte,
                                           responses [] SchnorrMResponse) SchnorrSignature {
    hct := suite.Cipher(cc)
    c := suite.Secret().Pick(hct)           // H(m||r)

    var r abstract.Secret = responses[0].R

    for _, response := range responses[1:] {
        r.Add(r, response.R)
    }

    return SchnorrSignature{S: r, E: c}
}



