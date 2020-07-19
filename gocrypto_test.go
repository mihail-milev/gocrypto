/*************************************************

This source code is licensed under the MIT license

Copyright 2020 Erik Bernoth

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

import "testing"
import "crypto/aes"
import "fmt"
import "bytes"

func TestSymmetricEncryption(t *testing.T) {
	pwd := "thisissecure"
	msg := "hello test"
	msgb := []byte(msg)
	// no clue why there's a wrapper but as test principle is to not change
	// too much at once I leave it like that and grab the Container from it
	// afterwards
	sutWrapper := New(&pwd)
	if sutWrapper.Result != nil {
		panic("Could not create sut")
	}
	sut := sutWrapper.Container
	key, encrypted := sut.SymmetricEncrypt(&msgb)
	sut.SymmetricDecrypt(key, encrypted)
	decrypted_untrimmed := (*encrypted)[aes.BlockSize:]
	// remove padding that was added to complete block size
	decrypted := string(bytes.Trim(decrypted_untrimmed, "\x00"))

	if decrypted != msg {
		fmt.Printf("hexes of msg '%q' hexes of decrypted '%q'\n", msg, decrypted)
		t.Errorf("expected '%s' but got '%s'", msg, decrypted)
	}
}
