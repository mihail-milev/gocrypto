/*************************************************

This source code is licensed under the MIT license

Copyright 2020 Mihail Milev

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*************************************************/

package gocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"unsafe"
)

const (
	WRAP_SIZE = 64
)

type PasswordReader struct {
	password *string
}

func (pr *PasswordReader) Read(p []byte) (n int, err error) {
	count := 0
	passlen := len(*(pr.password))
	for i := 0; i < len(p); i += passlen {
		if i+passlen <= len(p) {
			copy(p[i:i+passlen], *(pr.password))
			count += passlen
		} else {
			delta := len(p) - i
			copy(p[i:i+delta], (*(pr.password))[:delta])
			count += delta
		}
	}
	return count, nil
}

func createPasswordReader(passwd *string) *PasswordReader {
	return &PasswordReader{password: passwd}
}

func destroyMemoryLocation(location uintptr, length int) error {
	randdata := make([]byte, length)
	bytesread, err := rand.Read(randdata)
	if err != nil {
		return err
	}
	if bytesread != length {
		return errors.New("Random data length not equal to needed length")
	}
	for offs := 0; offs < length; offs++ {
		v := (*byte)(unsafe.Pointer(location + uintptr(offs)))
		*v = randdata[offs]
	}
	return nil
}

func destroyBigInt(bi *big.Int) error {
	if bi == nil {
		return errors.New("Supplied big Int is nil")
	}
	length := len(bi.Bytes())
	randdata := make([]byte, length)
	bytesread, err := rand.Read(randdata)
	if err != nil {
		return err
	}
	if bytesread != length {
		return errors.New("Random data length not equal to needed length")
	}
	bi.SetBytes(randdata)
	return nil
}

type Container struct {
	privateKey *[]byte
	publicKey  *[]byte
}

type ContainerCreateResult struct {
	Container *Container
	Result    error
}

func New(passwd *string) *ContainerCreateResult {
	if passwd == nil {
		return &ContainerCreateResult{Container: nil, Result: errors.New("Password pointer may not be nil")}
	}
	if len(*passwd) < 1 {
		return &ContainerCreateResult{Container: nil, Result: errors.New("Password may not be empty")}
	}
	passReader := createPasswordReader(passwd)
	privk, x, y, err := elliptic.GenerateKey(elliptic.P521(), passReader)
	errd := destroyMemoryLocation(uintptr(unsafe.Pointer(passReader)), int(unsafe.Sizeof(passReader)))
	if errd != nil {
		return &ContainerCreateResult{Container: nil, Result: errd}
	}
	if err != nil {
		return &ContainerCreateResult{Container: nil, Result: err}
	}
	pubk := elliptic.Marshal(elliptic.P521(), x, y)
	destroyBigInt(x)
	destroyBigInt(y)
	return &ContainerCreateResult{Container: &Container{privateKey: &privk, publicKey: &pubk}, Result: nil}
}

func (c *Container) Destroy() error {
	randdata1 := make([]byte, len(*(c.privateKey)))
	randdata2 := make([]byte, len(*(c.publicKey)))
	bytesread1, err1 := rand.Read(randdata1)
	bytesread2, err2 := rand.Read(randdata2)
	if bytesread2 != len(randdata2) || bytesread1 != len(randdata1) {
		return errors.New("Unable to read enough random data")
	}
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	copy(*(c.privateKey), randdata1)
	copy(*(c.publicKey), randdata2)
	destroyMemoryLocation(uintptr(unsafe.Pointer(c)), int(unsafe.Sizeof(c)))
	return nil
}

func doStringWrap(item *string) *string {
	if item == nil {
		return nil
	}
	outp := ""
	og := int(math.Ceil(float64(len(*item))/float64(WRAP_SIZE))) * WRAP_SIZE
	for i := 0; i < og; i += WRAP_SIZE {
		if i+WRAP_SIZE <= len(*item) {
			outp += (*item)[i:i+WRAP_SIZE] + "\n"
		} else {
			delta := len(*item) - i
			outp += (*item)[i:i+delta] + "\n"
		}
	}
	return &outp
}

func (c *Container) GetPublicKeyPem(identifier *string) string {
	pemkey := base64.StdEncoding.EncodeToString(*(c.publicKey))
	wrapped := doStringWrap(&pemkey)
	pb := *(*[]byte)(unsafe.Pointer(&pemkey))
	rand.Read(pb)
	return "-----BEGIN EC PUBLIC KEY FOR " + *identifier + "-----\n" +
		*wrapped +
		"-----END EC PUBLIC KEY FOR " + *identifier + "-----"
}

func marshalFour(A, B, C, D *big.Int) *[]byte {
	if A == nil || B == nil || C == nil || D == nil {
		return nil
	}
	ab := A.Bytes()
	bb := B.Bytes()
	cb := C.Bytes()
	db := D.Bytes()
	if len(ab) > 255 || len(bb) > 255 || len(cb) > 255 || len(db) > 255 {
		return nil
	}
	res := make([]byte, len(ab)+len(bb)+len(cb)+len(db)+4)
	if len(res) != len(ab)+len(bb)+len(cb)+len(db)+4 {
		return nil
	}
	res[0] = byte(len(ab))
	res[1] = byte(len(bb))
	res[2] = byte(len(cb))
	res[3] = byte(len(db))
	copy(res[4:len(ab)+4], ab)
	copy(res[len(ab)+4:len(ab)+len(bb)+4], bb)
	copy(res[len(ab)+len(bb)+4:len(ab)+len(bb)+len(cb)+4], cb)
	copy(res[len(ab)+len(bb)+len(cb)+4:], db)
	rand.Read(ab)
	rand.Read(bb)
	rand.Read(cb)
	rand.Read(db)
	return &res
}

func unmarshalFour(marshaled *[]byte) (*big.Int, *big.Int, *big.Int, *big.Int) {
	if marshaled == nil || len(*marshaled) < 4 {
		return nil, nil, nil, nil
	}
	lenab := (*marshaled)[0]
	lenbb := (*marshaled)[1]
	lencb := (*marshaled)[2]
	lendb := (*marshaled)[3]
	if len(*marshaled) < int(lenab)+int(lenbb)+int(lencb)+int(lendb)+4 {
		return nil, nil, nil, nil
	}
	A := big.NewInt(0)
	B := big.NewInt(0)
	C := big.NewInt(0)
	D := big.NewInt(0)
	A.SetBytes((*marshaled)[4 : lenab+4])
	B.SetBytes((*marshaled)[lenab+4 : lenab+lenbb+4])
	C.SetBytes((*marshaled)[lenab+lenbb+4 : lenab+lenbb+lencb+4])
	D.SetBytes((*marshaled)[lenab+lenbb+lencb+4:])
	return A, B, C, D
}

func (c *Container) AssymetricEncrypt(msg *[]byte) *[]byte {
	if len(*msg) > 64 {
		return nil
	}
	// step 1: map string to point
	M1 := big.NewInt(0)
	M1.SetBytes([]byte(*msg))
	M1n := new(big.Int)
	M1n.Mul(M1, elliptic.P521().Params().N)
	M1q := new(big.Int)
	M1q.Exp(M1, big.NewInt(3), nil)
	M2 := M1q.Add(M1q, M1n).Add(M1q, elliptic.P521().Params().B).Mod(M1q, elliptic.P521().Params().P)

	// step 2: calculate K and C
	k := make([]byte, len(M1.Bytes()))
	_, err := rand.Read(k)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read rand into k: %v\n", err)
		return nil
	}
	K1, K2 := elliptic.P521().ScalarBaseMult(k)
	x, y := elliptic.Unmarshal(elliptic.P521(), *(c.publicKey))
	A1, A2 := elliptic.P521().ScalarMult(x, y, k)
	destroyBigInt(x)
	destroyBigInt(y)
	C1, C2 := elliptic.P521().Add(A1, A2, M1, M2)

	destroyBigInt(A1)
	destroyBigInt(A2)
	destroyBigInt(M1)
	destroyBigInt(M2)
	destroyBigInt(M1n)
	destroyBigInt(M1q)

	// step 3: marshall and return
	retval := marshalFour(K1, K2, C1, C2)
	destroyBigInt(K1)
	destroyBigInt(K2)
	destroyBigInt(C1)
	destroyBigInt(C2)
	return retval
}

func (c *Container) AssymetricDecrypt(marshaled *[]byte) *[]byte {
	if marshaled == nil {
		return nil
	}
	// step 1: unmarshal K and C
	K1, K2, C1, C2 := unmarshalFour(marshaled)
	if K1 == nil || K2 == nil || C1 == nil || C2 == nil {
		return nil
	}

	// step 2: decrypt
	S1, S2 := elliptic.P521().ScalarMult(K1, K2, *(c.privateKey))
	R1, _ := elliptic.P521().Add(C1, C2, S1, S2.Neg(S2))

	destroyBigInt(K1)
	destroyBigInt(K2)
	destroyBigInt(C1)
	destroyBigInt(C2)
	destroyBigInt(S1)
	destroyBigInt(S2)

	// get final message
	finmsg := R1.Bytes()
	destroyBigInt(R1)
	return &finmsg
}

func (c *Container) SymmetricEncrypt(msg *[]byte) (*[]byte, *[]byte) {
	if msg == nil {
		return nil, nil
	}
	paddedsize := int(math.Ceil(float64(len(*msg))/float64(aes.BlockSize)) * aes.BlockSize)
	paddedcont := make([]byte, paddedsize)
	if len(paddedcont) != paddedsize {
		return nil, nil
	}
	copy(paddedcont[:len(*msg)], *msg)
	for i := len(*msg); i < paddedsize; i++ {
		paddedcont[i] = 0
	}
	encrypted := make([]byte, aes.BlockSize+paddedsize)
	if len(encrypted) != aes.BlockSize+paddedsize {
		return nil, nil
	}
	ivbytesread, err := rand.Read(encrypted[:aes.BlockSize])
	if ivbytesread != aes.BlockSize || err != nil {
		return nil, nil
	}
	key := make([]byte, 32)
	if len(key) != 32 {
		return nil, nil
	}
	keybytesread, err := rand.Read(key)
	if err != nil || keybytesread != 32 {
		return nil, nil
	}
	cipherblock, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil
	}
	mode := cipher.NewCBCEncrypter(cipherblock, encrypted[:aes.BlockSize])
	mode.CryptBlocks(encrypted[aes.BlockSize:], paddedcont)
	rand.Read(paddedcont)
	return &key, &encrypted
}

func (c *Container) SymmetricDecrypt(key, encrypted *[]byte) error {
	if key == nil {
		return errors.New("no key to decrypt with")
	}
	if encrypted == nil {
		return errors.New("no ciphertext to decrypt")
	}
	if len(*key) != 32 || len(*encrypted) < aes.BlockSize+1 || len(*encrypted)%aes.BlockSize != 0 {
		return errors.New("encrypted text does not fit into block size")
	}
	cipherblock, err := aes.NewCipher(*key)
	if err != nil {
		return errors.New("Couldn't create cipher")
	}
	mode := cipher.NewCBCDecrypter(cipherblock, (*encrypted)[:aes.BlockSize])
	mode.CryptBlocks((*encrypted)[aes.BlockSize:], (*encrypted)[aes.BlockSize:])

	return nil
}
