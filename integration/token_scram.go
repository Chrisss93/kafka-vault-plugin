package integration

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"

	"github.com/xdg-go/pbkdf2"
)

type progress int

const (
	ClientFirst progress = iota
	ServerFirst
	ClientFinal
	ServerFinal
	defaultMinIter = 4096
)

type TokenSCRAM struct {
	sync.RWMutex
	Hasher    func() hash.Hash
	TokenAuth bool

	username, password, authzID string
	minIters                    int

	progress                         progress
	msgHeader, msgClientFirst, nonce string
	serverSig                        []byte
	valid                            bool
	cache                            map[keyFactors]derivedKeys
}

func (k *TokenSCRAM) Begin(userName, password, authzID string) error {
	k.username, k.password, k.authzID = userName, password, authzID
	if k.minIters == 0 {
		k.minIters = defaultMinIter
	}
	if k.cache == nil {
		k.cache = make(map[keyFactors]derivedKeys)
	}
	if k.Hasher == nil {
		return fmt.Errorf("SCRAMClient has no specified Hasher")
	}
	return nil
}

func (k *TokenSCRAM) Done() bool {
	return k.progress == ServerFinal
}

func (k *TokenSCRAM) Step(challenge string) (response string, err error) {
	switch k.progress {
	case ClientFirst:
		response, err = k.clientFirst()
		k.progress = ServerFirst
	case ServerFirst:
		response, err = k.clientFinal(challenge)
		k.progress = ClientFinal
	case ClientFinal:
		err = k.serverFinal(challenge)
		k.progress = ServerFinal
	default:
		err = fmt.Errorf("conversation already completed")
	}
	return
}

func (k *TokenSCRAM) clientFirst() (string, error) {
	// Values are cached for use in final message parameters
	k.msgHeader = k.gs2Header()
	k.nonce = k.NonceFn()
	k.msgClientFirst = fmt.Sprintf("n=%s,r=%s", encodeName(k.username), k.nonce)
	if k.TokenAuth {
		k.msgClientFirst += ",tokenauth=true"
	}

	return k.msgHeader + k.msgClientFirst, nil
}

func (k *TokenSCRAM) NonceFn() string {
	raw := make([]byte, 24)
	nonce := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	rand.Read(raw)
	base64.StdEncoding.Encode(nonce, raw)
	return string(nonce)
}

func (k *TokenSCRAM) clientFinal(serverMsg string) (string, error) {
	msgServerFirst, err := parseServerFirst(serverMsg)
	if err != nil {
		return "", err
	}

	// Check nonce prefix and update
	if !strings.HasPrefix(msgServerFirst.nonce, k.nonce) {
		return "", errors.New("server nonce did not extend client nonce")
	}
	k.nonce = msgServerFirst.nonce

	// Check iteration count vs minimum
	if msgServerFirst.iters < k.minIters {
		return "", fmt.Errorf("server requested too few iterations (%d)", msgServerFirst.iters)
	}

	// Create client-final-message-without-proof
	msgClientFinal := fmt.Sprintf("c=%s,r=%s", base64.StdEncoding.EncodeToString([]byte(k.msgHeader)), k.nonce)

	// Create auth message
	authMsg := k.msgClientFirst + "," + serverMsg + "," + msgClientFinal

	// Get derived keys from client cache
	dk := k.getDerivedKeys(keyFactors{Salt: string(msgServerFirst.salt), Iters: msgServerFirst.iters})

	// Create proof as clientkey XOR clientsignature
	clientSig := computeHMAC(k.Hasher, dk.StoredKey, []byte(authMsg))
	proof := xorBytes(dk.ClientKey, clientSig)

	// Cache ServerSignature for later validation
	k.serverSig = computeHMAC(k.Hasher, dk.ServerKey, []byte(authMsg))

	return fmt.Sprintf("%s,p=%s", msgClientFinal, base64.StdEncoding.EncodeToString(proof)), nil
}

func (k *TokenSCRAM) serverFinal(serverMsg string) error {
	msg, err := parseServerFinal(serverMsg)
	if err != nil {
		return err
	}

	if len(msg.err) > 0 {
		return fmt.Errorf("server error: %s", msg.err)
	}

	if !hmac.Equal(msg.verifier, k.serverSig) {
		return fmt.Errorf("server validation failed")
	}

	k.valid = true
	return nil
}

func (k *TokenSCRAM) getDerivedKeys(kf keyFactors) derivedKeys {
	dk, ok := k.getCache(kf)
	if !ok {
		h := k.Hasher()
		saltedPassword := pbkdf2.Key([]byte(k.password), []byte(kf.Salt), kf.Iters, h.Size(), k.Hasher)
		clientKey := computeHMAC(k.Hasher, saltedPassword, []byte("Client Key"))

		clientHash := k.Hasher()
		clientHash.Write(clientKey)

		dk = derivedKeys{
			ClientKey: clientKey,
			StoredKey: clientHash.Sum(nil),
			ServerKey: computeHMAC(k.Hasher, saltedPassword, []byte("Server Key")),
		}
		k.setCache(kf, dk)
	}
	return dk
}

func (k *TokenSCRAM) gs2Header() string {
	if k.authzID == "" {
		return "n,,"
	}
	return fmt.Sprintf("n,%s,", encodeName(k.authzID))
}

func computeHMAC(hg func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(hg, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (s *TokenSCRAM) getCache(kf keyFactors) (derivedKeys, bool) {
	s.RLock()
	defer s.RUnlock()
	dk, ok := s.cache[kf]
	return dk, ok
}

func (s *TokenSCRAM) setCache(kf keyFactors, dk derivedKeys) {
	s.Lock()
	defer s.Unlock()
	s.cache[kf] = dk
}

func encodeName(s string) string {
	return strings.Replace(strings.Replace(s, "=", "=3D", -1), ",", "=2C", -1)
}

func xorBytes(a, b []byte) []byte {
	// TODO check a & b are same length, or just xor to smallest
	xor := make([]byte, len(a))
	for i := range a {
		xor[i] = a[i] ^ b[i]
	}
	return xor
}

type derivedKeys struct {
	ClientKey []byte
	StoredKey []byte
	ServerKey []byte
}

type keyFactors struct {
	Salt  string
	Iters int
}
