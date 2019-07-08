package authorisation

import (
	"crypto/rsa"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

type (
	JwkProvider interface {
		GetKey(keyID string) (*rsa.PublicKey, error)
	}

	Func func(key string) (*rsa.PublicKey, error)

	Memo struct{ requests chan request }

	result struct {
		value *rsa.PublicKey
		error error
	}

	entry struct {
		res   result
		ready chan struct{} // closed when res is ready
	}

	request struct {
		key      string
		response chan<- result // the client wants a single result
	}
)

func NewURLJwkProvider(url string) JwkProvider {
	return New(func(keyID string) (*rsa.PublicKey, error) { return GetKey(keyID, url) })
}

func GetKey(keyID string, url string) (*rsa.PublicKey, error) {
	data, err := fetch(url)
	if err != nil {
		return nil, err
	}

	jwkSet, err := ParseJwkSet(data)
	if err != nil {
		return nil, err
	}

	return getPublicKey(jwkSet, keyID)
}

func fetch(url string) ([]byte, error) {
	resp, err := http.Get(url) // nolint
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch jwks with url: %v", url)
	}

	defer func() {
		if closeErr := resp.Body.Close(); err == nil {
			err = closeErr
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, err
}

func ParseJwkSet(data []byte) (*jwk.Set, error) {
	jwkSet := &jwk.Set{}

	if err := jwkSet.UnmarshalJSON(data); err != nil {
		return nil, err
	}

	return jwkSet, nil
}

func getPublicKey(set *jwk.Set, keyID string) (*rsa.PublicKey, error) {
	keys := set.LookupKeyID(keyID)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no key found for ID: %v", keyID)
	}
	if len(keys) > 1 {
		return nil, fmt.Errorf("multiple keys found for ID: %v", keyID)
	}

	key, err := keys[0].Materialize()
	if err != nil {
		return nil, err
	}

	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("cert not *rsa.PublicKey")
	}

	return publicKey, nil
}

func New(f Func) *Memo {
	memo := &Memo{requests: make(chan request)}
	go memo.server(f)
	return memo
}

func (memo *Memo) GetKey(key string) (*rsa.PublicKey, error) {
	response := make(chan result)
	memo.requests <- request{key, response}
	res := <-response
	return res.value, res.error
}

func (memo *Memo) Close() { close(memo.requests) }

func (memo *Memo) server(f Func) {
	cache := make(map[string]*entry)
	for req := range memo.requests {
		e := cache[req.key]
		if e == nil {
			e = &entry{ready: make(chan struct{})}
			cache[req.key] = e
			go e.call(f, req.key)
		}
		go e.deliver(req.response)
	}
}

func (e *entry) call(f Func, key string) {
	e.res.value, e.res.error = f(key)
	close(e.ready)
}

func (e *entry) deliver(response chan<- result) {
	<-e.ready
	response <- e.res
}
