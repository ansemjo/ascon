# ansemjo/ascon

This is a Go binding for the [Ascon-128 cipher](https://ascon.iaik.tugraz.at/specification.html),
which is the preferred cipher for use in lightweight applications from the
[CAESAR portfolio](https://competitions.cr.yp.to/caesar-submissions.html).

It implements the `cipher.AEAD` interface:

```go
package main

import (
  // "..."
  "github.com/ansemjo/ascon"
)

func main() {

  // [...]

  // initialize with 16 byte key
  aead, err := ascon.New(key)
  if err != nil {
    panic("failed aead init")
  }

  // seal plaintext
  ct := aead.Seal(nil, nonce, plaintext, associated)

  // open ciphertext
  pt, err := a.Open(nil, nonce, ct, associated)
  if err != nil {
    panic(err.Error())
  }

  // [...]

}
```

Currently binds to the optimized 64 bit implementation of `ascon128v12` from
[ascon/crypto_aead](https://github.com/ascon/crypto_aead).

## DISCLAIMER

I am not a professional cryptographer. This is simply a binding to toy around with an interesting
new cipher and should be tested and audited thoroughly before use. Especially because I am using
lots of `unsafe.Pointer()`'s here.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.