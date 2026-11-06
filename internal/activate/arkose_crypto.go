package activate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"unicode/utf16"
)

func parseArkPEM(js string) (*rsa.PublicKey, error) {
	for _, block := range arkPEMCandidates(js) {
		der, _ := pem.Decode([]byte(block))
		if der == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(der.Bytes)
		if err != nil {
			if key, err2 := x509.ParsePKCS1PublicKey(der.Bytes); err2 == nil {
				return key, nil
			}
			continue
		}
		key, ok := pub.(*rsa.PublicKey)
		if ok {
			return key, nil
		}
	}
	return nil, fmt.Errorf("验证码公钥没取到")
}

func arkPEMCandidates(js string) []string {
	variants := []string{
		js,
		strings.ReplaceAll(js, `\n`, "\n"),
		strings.ReplaceAll(js, `\\n`, "\n"),
		strings.ReplaceAll(strings.ReplaceAll(js, `\n`, "\n"), `\r`, ""),
	}
	var out []string
	seen := map[string]struct{}{}
	for _, text := range variants {
		for _, begin := range []string{"-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----"} {
			end := "-----END PUBLIC KEY-----"
			if strings.Contains(begin, "RSA") {
				end = "-----END RSA PUBLIC KEY-----"
			}
			i := strings.Index(text, begin)
			j := strings.Index(text, end)
			if i < 0 || j < i {
				continue
			}
			block := text[i : j+len(end)]
			block = strings.ReplaceAll(block, `\n`, "\n")
			block = strings.ReplaceAll(block, `\r`, "")
			if _, ok := seen[block]; ok {
				continue
			}
			seen[block] = struct{}{}
			out = append(out, block)
		}
	}
	return out
}

// encryptFingerprint seals the pack the way the Arkose script does:
// base64(iv) + base64(tag) + base64(RSA-OAEP-SHA256(aes key)) + base64(ciphertext).
func encryptFingerprint(plain []byte, pub *rsa.PublicKey) (string, error) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plain, nil)
	if len(sealed) < gcm.Overhead() {
		return "", fmt.Errorf("指纹加密失败")
	}
	ct := sealed[:len(sealed)-gcm.Overhead()]
	tag := sealed[len(sealed)-gcm.Overhead():]
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	if err != nil {
		return "", err
	}
	return b64(iv) + b64(tag) + b64(wrapped) + b64(ct), nil
}

func buildKey(master, saltHex string) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, err
	}
	r := append([]byte(master), salt...)
	n0 := md5.Sum(r)
	n1 := md5.Sum(append(n0[:], r...))
	n2 := md5.Sum(append(n1[:], r...))
	out := append(append(n0[:], n1[:]...), n2[:]...)
	return out[:32], nil
}

// encryptPayload is the AES-CBC envelope used for a guess and for tguess.
func encryptPayload(plain, master string) (string, error) {
	salt := make([]byte, 8)
	iv := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(salt)
	key, err := buildKey(master, saltHex)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7([]byte(plain), aes.BlockSize)
	dst := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, padded)
	return fmt.Sprintf(`{"ct":"%s","iv":"%s","s":"%s"}`, b64(dst), hex.EncodeToString(iv), saltHex), nil
}

func pkcs7(b []byte, size int) []byte {
	n := size - (len(b) % size)
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// murmur3x64 is the Arkose fe digest: each UTF-16 code unit contributes its low byte,
// and the length mixed in is the number of code units.
func murmur3x64(text string) string {
	units := utf16.Encode([]rune(text))
	b := make([]byte, len(units))
	for i, u := range units {
		b[i] = byte(u)
	}
	const (
		c1 = 0x87c37b91114253d5
		c2 = 0x4cf5ad432745937f
	)
	n := len(b) % 16
	s := len(b) - n
	var h1, h2 uint64
	for y := 0; y < s; y += 16 {
		k1 := u64le(b[y : y+8])
		k2 := u64le(b[y+8 : y+16])
		k1 = rotl(k1*c1, 31) * c2
		h1 ^= k1
		h1 = rotl(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729
		k2 = rotl(k2*c2, 33) * c1
		h2 ^= k2
		h2 = rotl(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}
	var k1, k2 uint64
	y := s
	tail := n
	if tail >= 15 {
		k2 |= uint64(b[y+14]) << 48
	}
	if tail >= 14 {
		k2 |= uint64(b[y+13]) << 40
	}
	if tail >= 13 {
		k2 |= uint64(b[y+12]) << 32
	}
	if tail >= 12 {
		k2 |= uint64(b[y+11]) << 24
	}
	if tail >= 11 {
		k2 |= uint64(b[y+10]) << 16
	}
	if tail >= 10 {
		k2 |= uint64(b[y+9]) << 8
	}
	if tail >= 9 {
		k2 |= uint64(b[y+8])
		k2 = rotl(k2*c2, 33) * c1
		h2 ^= k2
	}
	if tail >= 8 {
		k1 |= uint64(b[y+7]) << 56
	}
	if tail >= 7 {
		k1 |= uint64(b[y+6]) << 48
	}
	if tail >= 6 {
		k1 |= uint64(b[y+5]) << 40
	}
	if tail >= 5 {
		k1 |= uint64(b[y+4]) << 32
	}
	if tail >= 4 {
		k1 |= uint64(b[y+3]) << 24
	}
	if tail >= 3 {
		k1 |= uint64(b[y+2]) << 16
	}
	if tail >= 2 {
		k1 |= uint64(b[y+1]) << 8
	}
	if tail >= 1 {
		k1 |= uint64(b[y])
		k1 = rotl(k1*c1, 31) * c2
		h1 ^= k1
	}
	h1 ^= uint64(len(b))
	h2 ^= uint64(len(b))
	h1 += h2
	h2 += h1
	h1 = fmix(h1)
	h2 = fmix(h2)
	h1 += h2
	h2 += h1
	return fmt.Sprintf("%016x%016x", h1, h2)
}

func u64le(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = (v << 8) | uint64(b[i])
	}
	return v
}

func rotl(x uint64, r uint) uint64 {
	r %= 64
	if r == 0 {
		return x
	}
	return (x << r) | (x >> (64 - r))
}

func fmix(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}
