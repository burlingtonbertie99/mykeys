package keys

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"sort"
	"strconv"
	"sync"
	"time"

	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"github.com/iancoleman/orderedmap"
	"net/http"
)

// EdX25519 key type.
const SGXHSM KeyType = "sgxhsm"

//const sgxhsmKeyHRP string = "sgx"

// SignOverhead alias for (nacl) sign.Overhead.
//const SignOverhead = sign.Overhead

// SGXHSMPublicKey is the public part of SGXHSM key pair.
type SGXHSMPublicKey struct {
	id        ID
	publicKey *[ed25519.PublicKeySize]byte
}

// SGXHSMKey SGXHSMPublicKey is a SGXHSM key capable of signing and encryption
type SGXHSMKey struct {
	privateKey *[ed25519.PrivateKeySize]byte
	publicKey  *EdX25519PublicKey
}

func (k *SGXHSMKey) Public() []byte {
	//TODO implement me
	panic("implement me")
}

// NewSGXHSMKeyFromPrivateKey constructs EdX25519Key from a private key.
// The public key is derived from the private key.
func NewSGXHSMKeyFromPrivateKey(privateKey *[ed25519.PrivateKeySize]byte) *EdX25519Key {
	k := &EdX25519Key{}
	if err := k.setPrivateKey(privateKey[:]); err != nil {
		panic(err)
	}
	return k
}

/*
func (k *SGXHSMKey) setPrivateKey(b []byte) error {
	if len(b) != ed25519.PrivateKeySize {
		return errors.Errorf("invalid private key length %d", len(b))
	}
	// Derive public key from private key
	edpk := ed25519.PrivateKey(b)
	publicKey := edpk.Public().(ed25519.PublicKey)
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.Errorf("invalid public key bytes (len=%d)", len(publicKey))
	}

	var privateKeyBytes [ed25519.PrivateKeySize]byte
	copy(privateKeyBytes[:], b[:ed25519.PrivateKeySize])

	var publicKeyBytes [ed25519.PublicKeySize]byte
	copy(publicKeyBytes[:], publicKey[:ed25519.PublicKeySize])

	k.privateKey = &privateKeyBytes
	k.publicKey = NewSGXHSMPublicKey(&publicKeyBytes)
	return nil
}
*/
// X25519Key converts EdX25519Key to X25519Key.
func (k *SGXHSMKey) SGXHSMKey() *X25519Key {
	secretKey := ed25519PrivateKeyToCurve25519(ed25519.PrivateKey(k.privateKey[:]))
	if len(secretKey) != 32 {
		panic("failed to convert key: invalid secret key bytes")
	}
	return NewX25519KeyFromPrivateKey(Bytes32(secretKey))
}

// ID ...
func (k *SGXHSMKey) ID() ID {
	return k.publicKey.ID()
}

// Type ...
func (k *SGXHSMKey) Type() KeyType {
	return EdX25519
}

// Private ...
func (k *SGXHSMKey) Private() []byte {
	return k.privateKey[:]
}

// Public ...
//func (k *SGXHSMKey) Public() []byte {
//return k.PublicKey().Public()
//}

// Signer interface.
func (k *SGXHSMKey) Signer() crypto.Signer {
	return ed25519.PrivateKey(k.Private())
}

/*
func (k *SGXHSMKey) PaperKey() string {
	s, err := encoding.BytesToPhrase(k.Seed()[:])
	if err != nil {
		panic(err)
	}
	return s
}

*/
/*
// MarshalText for encoding.TextMarshaler interface.
func (k *SGXHSMKey) MarshalText() ([]byte, error) {
	return []byte(encoding.MustEncode(k.Seed()[:], encoding.Base64)), nil
}
*/

/*
// UnmarshalText for encoding.TextUnmarshaler interface.
func (k *SGXHSMKey) UnmarshalText(s []byte) error {
	b, err := encoding.Decode(string(s), encoding.Base64)
	if err != nil {
		return err
	}
	var privateKey []byte
	if len(b) == 32 {
		privateKey = ed25519.NewKeyFromSeed(b)
	} else {
		privateKey = b
	}
	if err := k.setPrivateKey(privateKey); err != nil {
		return err
	}
	return nil
}
*/
// Equal returns true if equal to key.
func (k *SGXHSMKey) Equal(o *EdX25519Key) bool {
	return subtle.ConstantTimeCompare(k.Private(), o.Private()) == 1
}

// NewSGXHSMPublicKey creates a EdX25519PublicKey.
func NewSGXHSMPublicKey(b *[ed25519.PublicKeySize]byte) *SGXHSMPublicKey {
	return &SGXHSMPublicKey{
		id:        MustID(edx25519KeyHRP, b[:]),
		publicKey: b,
	}
}

/*
// NewSGXHSMPublicKeyFromID creates a EdX25519PublicKey from an ID.
func NewSGXHSMPublicKeyFromID(id ID) (*SGXHSMPublicKey, error) {
	if id == "" {
		return nil, errors.Errorf("empty id")
	}
	hrp, b, err := id.Decode()
	if err != nil {
		return nil, err
	}
	if hrp != sgxhsmKeyHRP {
		return nil, errors.Errorf("invalid key type for edx25519")
	}
	//if len(b) != sgxhsm.PublicKeySize {
	//return nil, errors.Errorf("invalid ed25519 public key bytes")
	//}
	return &SGXHSMPublicKey{
		id:        id,
		publicKey: Bytes32(b),
	}, nil
}

*/

/*
// SGXHSMMatch returns true if key IDs are equal or if either key matches their
// X25519 counterpart.
func SGXHSMMatch(expected ID, kid ID) bool {
	if expected == kid {
		return true
	}
	if expected.IsEdX25519() && kid.IsX25519() {
		err, _ := NewSGXHSMPublicKeyFromID(expected)
		if err != nil {
			return false
		}
		//return kid == spk.SGXHSMPublicKey().ID()

		return true
	}
	if kid.IsEdX25519() && expected.IsX25519() {
		err, _ := NewSGXHSMPublicKeyFromID(kid)
		if err != nil {
			return false
		}
		//return expected == spk.SGXHSMPublicKey().ID()
		return true
	}
	return false
}

*/

// ID for EdX25519Key.
func (k *SGXHSMPublicKey) ID() ID {
	return k.id
}

func (k *SGXHSMPublicKey) String() string {
	return k.id.String()
}

// Type ...
func (k *SGXHSMPublicKey) Type() KeyType {
	return SGXHSM
}

// Bytes ...
func (k *SGXHSMPublicKey) Bytes() []byte {
	return k.publicKey[:]
}

// Public ...
func (k *SGXHSMPublicKey) Public() []byte {
	return k.Bytes()
}

// Private returns nil.
func (k *SGXHSMPublicKey) Private() []byte {
	return nil
}

/*
// X25519PublicKey converts the ed25519 public key to a x25519 public key.
func (k *SGXHSMPublicKey) SGXHSMPublicKey() *SGXHSMPublicKey {
	edpk := sgxhsm.PublicKey(k.publicKey[:])
	bpk := ed25519PublicKeyToCurve25519(edpk)
	if len(bpk) != 32 {
		panic("unable to convert key: invalid public key bytes")
	}
	key := NewX25519PublicKey(Bytes32(bpk))
	// TODO: Copy metadata?
	// key.metadata = s.metadata
	return key
}

// Verify verifies a message and signature with public key and returns the
// signed bytes without the signature.
func (k *EdX25519PublicKey) Verify(b []byte) ([]byte, error) {
	if l := len(b); l < sign.Overhead {
		return nil, errors.Errorf("not enough data for signature")
	}
	_, ok := sign.Open(nil, b, k.publicKey)
	if !ok {
		return nil, ErrVerifyFailed
	}
	return b[sign.Overhead:], nil
}

// VerifyDetached verifies a detached message.
func (k *EdX25519PublicKey) VerifyDetached(sig []byte, b []byte) error {
	if len(sig) != sign.Overhead {
		return errors.Errorf("invalid sig bytes length")
	}
	if len(b) == 0 {
		return errors.Errorf("no bytes")
	}
	msg := bytesJoin(sig, b)
	_, err := k.Verify(msg)
	return err
}

// NewEdX25519KeyFromSeed constructs EdX25519Key from an ed25519 seed.
// The private key is derived from this seed and the public key is derived from the private key.
func NewEdX25519KeyFromSeed(seed *[ed25519.SeedSize]byte) *EdX25519Key {
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return NewSGXHSMKeyFromPrivateKey(Bytes64(privateKey))
}

// NewEdX25519KeyFromPaperKey constructs EdX25519Key from a paper key.
func NewEdX25519KeyFromPaperKey(paperKey string) (*EdX25519Key, error) {
	b, err := encoding.PhraseToBytes(paperKey, false)
	if err != nil {
		return nil, err
	}
	return NewEdX25519KeyFromSeed(b), nil
}


*/

/*
// Seed returns information on how to generate this key from ed25519 package seed.
func (k *SGXHSMPublicKey) Seed() *[ed25519.SeedSize]byte {
	pk := ed25519.PrivateKey(k.privateKey[:])
	return Bytes32(pk.Seed())
}
*/

/*
func (k *SGXHSMPublicKey) String() string {
	return k.publicKey.String()
}

// PublicKey returns public part.
func (k *SGXHSMPublicKey) PublicKey() *EdX25519PublicKey {
	return k.publicKey
}

// PrivateKey returns private key part.
func (k *SGXHSMPublicKey) PrivateKey() *[ed25519.PrivateKeySize]byte {
	return k.privateKey
}

// Sign bytes with the (sign) private key.
func (k *SGXHSMPublicKey) Sign(b []byte) []byte {
	return sign.Sign(nil, b, k.privateKey)
}

*/

// SignDetached sign bytes detached.
//func (k *SGXHSMPublicKey) SignDetached(b []byte) []byte {
//	return k.Sign(b)[:sign.Overhead]
//}

// GenerateSGXHSMKey generates a SGXHSMPublicKey (EdX25519).
func GenerateSGXHSMKey() string {
	logger.Infof("Generating SGXHSM key...")
	//seed := Rand32()
	//key := NewEdX25519KeyFromSeed(seed)
	//return key

	// HTTP endpoint
	posturl := "https://192.168.0.21:9002/ehsm?Action=ListKey"

	// JSON body
	body := []byte(`{
		"keyspec": "EH_AES_GCM_128",
		"origin": "EH_INTERNAL_KEY",
		"keyusage": "EH_KEYUSAGE_ENCRYPT_DECRYPT"
	}`)

	// Create a HTTP post request
	r, err := http.NewRequest("POST", posturl, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	r.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	res, err := client.Do(r)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	post := &Post{}
	derr := json.NewDecoder(res.Body).Decode(post)
	if derr != nil {
		panic(derr)
	}

	//	fmt.Println("Id:", post.Id)
	//	fmt.Println("Title:", post.Title)/
	//	fmt.Println("Body:", post.Body)
	//	fmt.Println("UserId:", post.UserId)

	var myclient Client

	myclient.appid = "eb77f9c4-3ae6-44e0-b9ef-4a4fd20e6582"
	myclient.apikey = "wWH4wPRTJvvAdviN069gB9dKhbLFDT44"
	myclient.addr = "https://localhost:9002/"

	keyid := ""
	keyid, err = myclient.CreateKey("EH_AES_GCM_128", "EH_INTERNAL_KEY", "EH_KEYUSAGE_ENCRYPT_DECRYPT")

	return keyid

}

func CreateKeyXXX(s string, s2 string, s3 string) {

}

type Post struct {
	APPID      string `json:"appid"`
	APIKEY     string `json:"apikey"`
	TimeStamep string `json:"timestamp"`
	ID         string `json:"id"`
	Keyspec    string `json:"keyspec"`
	Origin     string `json:"origin"`
	KeyUsage   string `json:"keyusage"`
}

/*
Description:
Create a customer master key(CMK) for the user,
which can be a symmetric or an asymmetric key,
for the symmetric cmk mainly used to wrap the datakey,
also can be used to encrypted an arbitrary set of bytes data(<6KB).
And for the asymmetric cmk mainly used to sign/verify
or asymmetric encrypt/decrypt datas(not for the datakey.)
Input:
keyspec

	-EH_AES_GCM_128,
	-EH_AES_GCM_256,
	-EH_RSA_2048,
	-EH_RSA_3072,
	-EH_EC_P256,
	-EH_EC_P521,
	-EH_SM2,
	-EH_SM4_CBC,
	-EH_HMAC,

origin

	-EH_INTERNAL_KEY (generated from the eHSM inside)
	-EH_EXTERNAL_KEY (generated by the customer and want to import into the eHSM),

keyusage

	-EH_KEYUSAGE_ENCRYPT_DECRYPT
	-EH_KEYUSAGE_SIGN_VERIFY

Output:
keyid -- A uinque keyid of the cmk.
*/
func (c *Client) CreateKey(keyspec, origin, keyusage string) (string, error) {
	// make JSON for createkey
	payload := orderedmap.New()
	if keyspec != "" {
		payload.Set("keyspec", keyspec)
	} else {
		return "", fmt.Errorf("Please input keyspec.")
	}
	if origin != "" {
		payload.Set("origin", origin)
	} else {
		return "", fmt.Errorf("Please input origin.")
	}

	if keyusage != "" {
		payload.Set("keyusage", keyusage)
	} else {
		return "", fmt.Errorf("Please input keyusage.")
	}

	params := c.initParams(payload)

	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	// call ehsm kms
	resp, err := c.doPost(params, "CreateKey")
	if err != nil {
		return "", err
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("result field is not a valid map")
	}

	keyid, ok := result["keyid"].(string)
	if !ok {
		return "", fmt.Errorf("keyid field is not a valid string")
	}
	return keyid, nil
}

// For production environment, the web server should request a formally issued
// certificate, and change the below skipVerify to False.
// TODO change this!!!!!
const skipVerify = true

func (c *Client) doPost(resquest *orderedmap.OrderedMap, action string) (map[string]interface{}, error) {
	// create an insecure Transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	// create an insecure Client
	client := &http.Client{Transport: tr}

	requestBody, err := json.Marshal(resquest)
	if err != nil {
		return nil, err
	}

	// call ehsm kms
	resp, err := client.Post(c.addr+"/ehsm?Action="+action, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var respJSON map[string]interface{}

	err = json.Unmarshal(body, &respJSON)
	if err != nil {
		return nil, err
	}

	if respJSON["code"].(float64) != 200 {
		return nil, fmt.Errorf(respJSON["message"].(string))
	}

	return respJSON, nil
}

type Client struct {
	modifyLock sync.RWMutex
	addr       string
	apikey     string
	appid      string
}

func (c *Client) initParams(payload *orderedmap.OrderedMap) *orderedmap.OrderedMap {
	params := orderedmap.New()
	params.Set("appid", c.appid)
	params.Set("payload", payload)
	params.Set("timestamp", strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))

	signString := paramsSortStr(params)
	hmacSha256 := hmac.New(sha256.New, []byte(c.apikey))
	hmacSha256.Write([]byte(signString))
	sign := base64.StdEncoding.EncodeToString(hmacSha256.Sum(nil))

	params.Set("sign", sign)
	return params
}

func paramsSortStr(signParams *orderedmap.OrderedMap) string {
	var str string
	sortedSignParams := sortMap(signParams)
	for _, k := range sortedSignParams.Keys() {
		v, _ := sortedSignParams.Get(k)
		if k == "payload" {
			payload := v.(*orderedmap.OrderedMap)
			str += "&" + k + "=" + paramsSortStr(payload)
		} else {
			str += fmt.Sprintf("&%s=%v", k, v)
		}
	}
	if len(str) > 0 {
		str = str[1:] // Remove leading "&"
	}
	return str
}

func sortMap(oldmap *orderedmap.OrderedMap) *orderedmap.OrderedMap {
	newmap := orderedmap.New()
	keys := oldmap.Keys()
	sort.Strings(keys)
	for _, key := range keys {
		value, _ := oldmap.Get(key)
		newmap.Set(key, value)
	}
	return newmap
}
