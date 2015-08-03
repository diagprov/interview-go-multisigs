
package crypto

/*
This file implements the blind signature scheme as described in the given paper.
In particular I would like to note that I have confused terminology a litte
given we are building a server/client architecture. In this case:

1. User/client are interchangeable. These sign the message but do so in a partially blind fashion
   as described.
2. Server/signer are interchangeable. This entity holds private parameters and can sign messages 
   given agreed information witht he user/client by answering challenges.

Of particular concern in my implementation is the Z-generation. The paper describes F(info) as a 
public key with no known private key; in order to generate a point on the curve we have effectively 
taken g^{F(info)} which means F(info) could act as a private key in a schnorr signature scheme. 
I am not sure if this breaks the security of the system. However, given some info we need to 
deterministically find a curve point, which we cannot do with the underlying library at present.

*/

import (
    //"bytes"
	"crypto/rand"
	"github.com/dedis/crypto/abstract"
	"golang.org/x/crypto/sha3"
)

// Represents he prviate parameters 
// generated in Fig 1. "signer"
// You'll also want to use Schnorr.go to generate
// a public/private keypair
type WISchnorrBlindPrivateParams struct {
	U         abstract.Secret
	S         abstract.Secret
	D         abstract.Secret
	Z         abstract.Point
	A         abstract.Point
	B         abstract.Point
}

/* GenerateZ takes some random agreed information and creates
   Z the "public-only" key that is witness-independent as per 
   the paper. We've probably broken that slightly in this implementation
   because I could not pick a point without generating it 
   via a Secret, instead of directly via a Point - that is, even as a 
   32-byte string, we cannot decode on C25519 (and this wouldn't work 
   for abstract suites anyway). 

   However, it demonstrates the idea.
*/
func GenerateZ (suite abstract.Suite, info[] byte) (abstract.Point, error) {
	
	hasher := sha3.New256()
    hasher.Write(info)
    zraw := hasher.Sum(nil)

    

    //I think this might be cheating
    zrawCt := suite.Cipher(zraw)

    zfactor := suite.Secret().Pick(zrawCt)
    Z := suite.Point()
    Z.Mul(nil, zfactor)

    // every 32-bit integer exists on Curve25519 only if we have the fullgroup
    // this should work, but doesn't.

    /*var Z abstract.Point
    zrawBuf := bytes.NewBuffer(zraw)
    err := abstract.Read(zrawBuf, &Z, suite);
    if err != nil {
        return nil, err
    }*/

    return Z, nil
}

// public parameters that can be transmitted to
// the end-user who wishes to request a signature
// where "transmit" could be embedding in the key
// since there's no requirement for this stage to
// be an online protocol
type WISchnorrPublicParams struct {
	A         abstract.Point
	B         abstract.Point
}

/* The challenge message is the structure the user 
   generates and passes to the server 
   in order for it to be signed.
   This is essentially just E.
*/
type WISchnorrChallengeMessage struct {
	E         abstract.Secret
}

// Generates all of the private parameters aside
// from the private / public key pair. Do that 
// separately.
func NewPrivateParams (suite abstract.Suite, info []byte ) (WISchnorrBlindPrivateParams, error) {

	r1 := make([]byte, 16)
	r2 := make([]byte, 16)
	r3 := make([]byte, 16)

	v := make([]byte, 16)
    _, err := rand.Read(r1)
    if err != nil {
        return WISchnorrBlindPrivateParams{}, err
    }
    _, err = rand.Read(r2)
    if err != nil {
        return WISchnorrBlindPrivateParams{}, err
    }
    _, err = rand.Read(r3)
    if err != nil {
        return WISchnorrBlindPrivateParams{}, err
    }
    _, err = rand.Read(v)
    if err != nil {
        return WISchnorrBlindPrivateParams{}, err
    }
    rc1 := suite.Cipher(r1)
    rc2 := suite.Cipher(r2)
    rc3 := suite.Cipher(r3)

    z, err := GenerateZ(suite, info)
    if err != nil {
        return WISchnorrBlindPrivateParams{}, err
    } 
    
    u := suite.Secret().Pick(rc1)         
    s := suite.Secret().Pick(rc2)  
    d := suite.Secret().Pick(rc3)

    a := suite.Point().Mul(nil, u) // g^u
    b1 := suite.Point().Mul(nil, s)  // g^s
    b2 := suite.Point().Mul(z, d)    // z^d
    b := suite.Point().Add(b1, b2)   // g^sz^d 

    return WISchnorrBlindPrivateParams{u, s, d, z, a, b}, nil
}

// Takes a private parameter "tuple" and extracts from it a 
// proper public "tuple"
func (this * WISchnorrBlindPrivateParams) DerivePubParams () WISchnorrPublicParams {
	return WISchnorrPublicParams{this.A, this.B}
}


/* The client parameter list is the structure 
   packing all those elements that the client owns
   but does not transmit. */
type WISchnorrClientParamersList struct {
	T1         abstract.Secret
	T2         abstract.Secret
	T3         abstract.Secret
	T4         abstract.Secret
	Z          abstract.Point
}

/* This function is responsible for producing the challenge message E to send back to the signer. */
func ClientGenerateChallenge (suite abstract.Suite, publicParameters WISchnorrPublicParams, pk SchnorrPublicKey, info []byte, msg []byte) (WISchnorrChallengeMessage, WISchnorrClientParamersList, error) {

	r1 := make([]byte, 16)
	r2 := make([]byte, 16)
	r3 := make([]byte, 16)
	r4 := make([]byte, 16)
    _, err := rand.Read(r1)
    if err != nil {
        return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
    }
    _, err = rand.Read(r2)
    if err != nil {
        return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
    }
    _, err = rand.Read(r3)
    if err != nil {
        return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
    }
    _, err = rand.Read(r4)
    if err != nil {
        return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
    }

    rc1 := suite.Cipher(r1)
    rc2 := suite.Cipher(r2)
    rc3 := suite.Cipher(r3)
    rc4 := suite.Cipher(r4)

    t1 := suite.Secret().Pick(rc1)         
    t2 := suite.Secret().Pick(rc2)  
    t3 := suite.Secret().Pick(rc3)
    t4 := suite.Secret().Pick(rc4)

    z, err := GenerateZ(suite, info)
    if err != nil {
        return WISchnorrChallengeMessage{}, WISchnorrClientParamersList{}, err
    }

    zraw, _ := z.MarshalBinary()

    packedParameters := WISchnorrClientParamersList{t1,t2,t3,t4,z}

    // There might be a better way to lay out this
    // code but it hardly matters.
    // The compiler will be issuing temporary vars
    // all over the show anyway.
    // At least this way I am sure
    // exactly what the code does.

    alpha1 := suite.Point()
    alpha1.Mul(nil, t1)
    alpha := suite.Point()
    alpha.Mul(pk.Y,  t2)
    alpha.Add(alpha, alpha1).Add(alpha, publicParameters.A)

    beta1 := suite.Point()
    beta1.Mul(nil, t3)
    beta := suite.Point()
    beta.Mul(z, t4).Add(beta, beta1).Add(beta, publicParameters.B)

    var combinedmsg []byte

    bAlpha, _ := alpha.MarshalBinary()
    bBeta, _ := beta.MarshalBinary()

    //zraw, _ := publicParameters.Z.MarshalBinary()

    combinedmsg = append(combinedmsg, bAlpha...)
    combinedmsg = append(combinedmsg, bBeta...)
    combinedmsg = append(combinedmsg, zraw...)
    combinedmsg = append(combinedmsg, msg...)

    hasher := sha3.New256()
    hasher.Write(combinedmsg)
    ee := hasher.Sum(nil)
    ect := suite.Cipher(ee)

    epsilon := suite.Secret().Pick(ect)

    e := suite.Secret()
    e.Sub(epsilon, t2).Sub(e, t4)

    return WISchnorrChallengeMessage{e}, packedParameters, nil
}

/* This is the response message the server sends back to the user */
type WISchnorrResponseMessage struct {
	R      abstract.Secret
	C      abstract.Secret
	S      abstract.Secret
	D      abstract.Secret
}

/* The servergenerateresponse function is fairly self explanatory - this function provides an answer 
   to the challenge message provided by the user. */
func ServerGenerateResponse (suite abstract.Suite, challenge WISchnorrChallengeMessage, privateParameters WISchnorrBlindPrivateParams, privKey SchnorrKeyset) WISchnorrResponseMessage {

	c := suite.Secret()
	c.Sub(challenge.E, privateParameters.D)
	r := suite.Secret()
	r.Mul(c, privKey.X).Sub(privateParameters.U, r)

	return WISchnorrResponseMessage{r, c, privateParameters.S, privateParameters.D}
}

/* This structure implements the elements of the blind signature as described in the paper 
   They match in order and are designed to "Look like" the greek symbols, so P=rho. W = omega, S=sigma, D=delta*/
type WIBlindSignature struct {
	P    abstract.Secret
	W    abstract.Secret
	S    abstract.Secret
	D    abstract.Secret
}

/* This is the function that given the client's challenge and response from the server is able to 
   compute the final blind signature. This is done on the user side (blindly to the signer). */
func ClientSignBlindly (suite abstract.Suite, clientParameters WISchnorrClientParamersList, responseMsg WISchnorrResponseMessage, pubKey SchnorrPublicKey, msg []byte) (WIBlindSignature, bool) {

	rho   := suite.Secret()
	omega := suite.Secret()
	sigma := suite.Secret()
	delta := suite.Secret()

	rho.Add(responseMsg.R, clientParameters.T1)
	omega.Add(responseMsg.C, clientParameters.T2)
	sigma.Add(responseMsg.S, clientParameters.T3)
	delta.Add(responseMsg.D, clientParameters.T4)

	gp := suite.Point()
	gp.Mul(nil, rho)
	
	yw := suite.Point()
	yw.Mul(pubKey.Y, omega)
	gpyw := suite.Point()

	gpyw.Add(gp, yw)
	bGpyw, _ := gpyw.MarshalBinary()

	gs := suite.Point()
	gs.Mul(nil, sigma)
	zd := suite.Point()
	zd.Mul(clientParameters.Z, delta)
	gszd := suite.Point()
	gszd.Add(gs, zd)
	bGszd, _ := gszd.MarshalBinary()

	bZ, _ := clientParameters.Z.MarshalBinary()

	var combinedmsg []byte


    combinedmsg = append(combinedmsg, bGpyw...)
    combinedmsg = append(combinedmsg, bGszd...)
    combinedmsg = append(combinedmsg, bZ...)
    combinedmsg = append(combinedmsg, msg...)

	hasher := sha3.New256()
    hasher.Write(combinedmsg)
    bSig := hasher.Sum(nil)
    bSigCt := suite.Cipher(bSig)

    sig := suite.Secret().Pick(bSigCt)

    vsig := suite.Secret()
    vsig.Add(omega, delta)

    //fmt.Println(sig)
    //fmt.Println(vsig)

    return WIBlindSignature{rho, omega, sigma, delta}, sig.Equal(vsig)
}



/* This function implements the verification protocol and can be used 
   by any party given a decoded schnorr signature, a 
   message and valid information. Invalid information will break the protocol
   and produce an invalid message; this is tested for in the unit test code. */
func VerifyBlindSignature (suite abstract.Suite, pk SchnorrPublicKey, sig WIBlindSignature, info []byte, msg[] byte) (bool, error) {

	z, err := GenerateZ(suite, info)
    if err != nil {
        return false, err
    }

	gp := suite.Point().Mul(nil, sig.P)
	yw := suite.Point().Mul(pk.Y, sig.W)
	gpyw := suite.Point().Add(gp, yw)

	gs := suite.Point().Mul(nil, sig.S)
	zd := suite.Point().Mul(z, sig.D)
	gszd := suite.Point().Add(gs, zd)

	bP1, _ := gpyw.MarshalBinary()
	bP2, _ := gszd.MarshalBinary()
	bZ, _ := z.MarshalBinary()

	var combinedmsg []byte

	combinedmsg = append(combinedmsg, bP1...)
    combinedmsg = append(combinedmsg, bP2...)
    combinedmsg = append(combinedmsg, bZ...)
    combinedmsg = append(combinedmsg, msg...)

	hasher := sha3.New256()
    hasher.Write(combinedmsg)
    bSig := hasher.Sum(nil)
    bSigCt := suite.Cipher(bSig)

	hsig := suite.Secret().Pick(bSigCt)

    vsig := suite.Secret()
    vsig.Add(sig.W, sig.D)

	return hsig.Equal(vsig), nil
}