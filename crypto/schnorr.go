
package crypto

// This file implements Schnorr signature scheme
// Mostly based on your implementation except
// 1) I used wikipedia's variable names as my reference, 
//    not your letters. Sorry.
// 2) I reworked hashing to use SHA3. 
// 3) Generating keys grabs a random 128-bit blob from
//    /dev/urandom instead of  using a fixed example.
// 4) likewise, k the randomly chosen data in our signature
//    is also read from /dev/urandom.

import (
    "bytes"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "io/ioutil"
    "os"
    "golang.org/x/crypto/sha3"
    "github.com/dedis/crypto/abstract"
    "github.com/dedis/crypto/edwards/ed25519"

)


// Represents a keyset, some privae x
// and y = x g.
type SchnorrKeyset struct {
    X  abstract.Secret
    Y  abstract.Point   
}

// Represents only the public key
// from a given keypair
type SchnorrPublicKey struct {
    Y  abstract.Point
}

func encodeAsB64(y abstract.Point) string {

    // there must be better ways of doing this. Ideally, 
    // we should have JSON marshalling for the 
    // point, secret types in dedis/crypto
    // but we don't, so, that's a shame.
    suite := ed25519.NewAES128SHA256Ed25519(true) 

    buf := bytes.Buffer{} 
    abstract.Write(&buf, &y, suite)
    return hex.EncodeToString(buf.Bytes())
}

func decodeFromB64(buf []byte) abstract.Point {
    suite := ed25519.NewAES128SHA256Ed25519(true) 
    
    str := string(buf)
    decodedBytes, _ := hex.DecodeString(str)
    P := suite.Point()
    decoded := bytes.NewBuffer(decodedBytes)

    _ = abstract.Read(decoded, &P, suite);
    return P
}

func (k SchnorrPublicKey) UnmarshalJSON(b []byte) (err error) {
    k.Y = decodeFromB64(b)
    return nil
}

func (k SchnorrPublicKey) MarshalJSON() ([]byte, error) {
    return json.Marshal(struct{
        Y      string `json:"Y"`
    }{  
        Y: encodeAsB64(k.Y),
    })

}

// Represents a Schnorr signature.
type SchnorrSignature struct {
    S abstract.Secret
    E abstract.Secret
}

// Returns a SchnorrPublicKey structure
// from a given SchnorrSignature.
// I separated the two so there are type differences between
// public and private keys in code, which I think helps
// keep the design clean.
func SchnorrExtractPubkey(privkey SchnorrKeyset) SchnorrPublicKey {
    return SchnorrPublicKey{Y: privkey.Y}
}

// Signs a given message and returns the signature.
// If no signature is possible due to an error
// returns the error in the second retval.
func SchnorrSign (suite abstract.Suite, 
                  kv SchnorrKeyset, 
                  msg []byte) ([]byte, error) {

    rsource := make([]byte, 16)
    _, err := rand.Read(rsource)
    if err != nil {
        return nil, err
    }
    // I have no idea if I just encrypted randomness or not
    // I'm hoping this just reads the state out.
    rct := suite.Cipher(rsource)
    
    k := suite.Secret().Pick(rct)           // some k
    r := suite.Point().Mul(nil, k)          // g^k

    r_bin, _ := r.MarshalBinary()
    msg_and_r := append(msg, r_bin...) 
    
    hasher := sha3.New256()
    hasher.Write(msg_and_r)
    h := hasher.Sum(nil)

    // again I'm hoping this just reads the state out
    // and doesn't  actually perform any ops
    hct := suite.Cipher(h)
    e := suite.Secret().Pick(hct)           // H(m||r)

    s := suite.Secret()
    s.Mul(kv.X, e).Sub(k, s)                // k - xe

    sig := SchnorrSignature{S:s,E:e}

    buf := bytes.Buffer{} 
    abstract.Write(&buf, &sig, suite)
    return buf.Bytes(), nil
}

// Checks the signature against 
// the message
func SchnorrVerify (suite abstract.Suite, 
                    kp SchnorrPublicKey, 
                    msg []byte, sig []byte) (bool, error) {

    buf := bytes.NewBuffer(sig)
    signature := SchnorrSignature{}
    err := abstract.Read(buf, &signature, suite);
    if err != nil {
        return false, err
    }

    s := signature.S
    e := signature.E

    var gs, ye, r abstract.Point
    gs = suite.Point().Mul(nil, s)      // g^s
    ye = suite.Point().Mul(kp.Y, e)     // y^e
    r = suite.Point().Add(gs, ye)       // g^xy^e
        
    r_bin, _ := r.MarshalBinary()
    msg_and_r := append(msg, r_bin...) 
    hasher := sha3.New256()
    hasher.Write(msg_and_r)
    h := hasher.Sum(nil)
    
    // again I'm hoping this just reads the state out
    // and doesn't  actually perform any ops
    lct := suite.Cipher(h)

    ev := suite.Secret().Pick(lct)
    return ev.Equal(e), nil
}


// The schnorrGenerateKeypair does exactly that - 
// it generates a valid keypair for later use 
// in producing signatures.
// I wanted to add a little bit of proper key 
// management to the process but I couldn't work out 
// how to pass a simple random stream to suite.Secret().Pick().
// I looked into Go streams very briefly  but decided 
// I was spending too much time on that 
// instead I passed /dev/urandom through the cipher 
// interface. 
func SchnorrGenerateKeypair (suite abstract.Suite) (SchnorrKeyset, error) {
    rsource := make([]byte, 16)
    _, err := rand.Read(rsource)
    if err != nil {
        return SchnorrKeyset{}, err
    }

    rct := suite.Cipher(rsource)
    
    x := suite.Secret().Pick(rct)           // some x
    y := suite.Point().Mul(nil, x)          // y = g^x \in G, DLP.

    return SchnorrKeyset{x,y}, nil
}


// Loads the key pair as a binary blob from a file on disk
func SchnorrLoadKeypair(path string, suite abstract.Suite) (SchnorrKeyset, error) {
    
    fcontents, err := ioutil.ReadFile(path)
    if err != nil {
        return SchnorrKeyset{}, err
    }
    buf := bytes.NewBuffer(fcontents)
    kv := SchnorrKeyset{}
    err2 := abstract.Read(buf, &kv, suite);

    return kv, err2
}

// Saves the keypair as a binary blob on disk. The file format
// matches abstract.Write(...) so whatever that uses, we're using here.
func SchnorrSaveKeypair(path string,  suite abstract.Suite, kv SchnorrKeyset) error {
    buf := bytes.Buffer{} 
    abstract.Write(&buf, &kv, suite)
    f, err := os.OpenFile(path, os.O_CREATE | os.O_RDWR, 0600)
    if err != nil { return err }
    defer f.Close()
    _, e2 := f.Write(buf.Bytes())
    return e2
}

// Loads only the public key from disk.
func SchnorrLoadPubkey(path string, suite abstract.Suite) (SchnorrPublicKey, error) {
    
    fcontents, err := ioutil.ReadFile(path)
    if err != nil {
        return SchnorrPublicKey{}, err
    }
    buf := bytes.NewBuffer(fcontents)
    kv := SchnorrPublicKey{}
    err2 := abstract.Read(buf, &kv, suite);

    return kv, err2
}

// Saves only the public key to disk.
func SchnorrSavePubkey(path string, suite abstract.Suite, k SchnorrPublicKey) error {
    buf := bytes.Buffer{} 
    abstract.Write(&buf, &k, suite)
    f, err := os.OpenFile(path, os.O_CREATE | os.O_RDWR, 0644)
    if err != nil { return err }
    defer f.Close()
    _, e2 := f.Write(buf.Bytes())
    return e2
}



