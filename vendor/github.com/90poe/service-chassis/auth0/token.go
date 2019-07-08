package auth0

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

const (
	//Cache expiry = token expiry minus this value so that clients have a window for use before token expiry
	defaultTokenUsageWindow = 30 * time.Second
)

type Service interface {
	GetBearerToken(audience, clientID, clientSecret string) (*BearerToken, error)
}

type cachedTokenProvider struct {
	tenant                  string
	apiURLHost              string
	cache                   *cache.Cache
	usageTokenWindowSeconds time.Duration
}

type BearerToken struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	GrantType    string `json:"grant_type"`
}

func NewService(tenant string, apiURLHost string) Service {
	return &cachedTokenProvider{
		apiURLHost:              apiURLHost,
		cache:                   cache.New(5*time.Minute, 10*time.Minute),
		tenant:                  tenant,
		usageTokenWindowSeconds: defaultTokenUsageWindow,
	}
}

func (service cachedTokenProvider) WithUsageWindow(seconds time.Duration) Service {
	service.usageTokenWindowSeconds = seconds
	return service
}

func (service cachedTokenProvider) GetBearerToken(audience, clientID, clientSecret string) (*BearerToken, error) {
	tokenKey := fmt.Sprintf("%s:%s:%s", audience, service.tenant, clientID)

	if bearerToken, found := service.cache.Get(tokenKey); found {
		return bearerToken.(*BearerToken), nil
	}

	bearerToken, err := GetBearerToken(service.apiURLHost, audience, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	cacheExpiry := (time.Second * time.Duration(bearerToken.ExpiresIn)) - service.usageTokenWindowSeconds
	if cacheExpiry > 0 {
		service.cache.Set(tokenKey, bearerToken, cacheExpiry)
	}

	return bearerToken, nil
}

func GetBearerToken(apiURLHost, audience, clientID, clientSecret string) (*BearerToken, error) {
	reqData := &tokenRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Audience:     audience,
		GrantType:    "client_credentials",
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	res, err := http.Post(
		fmt.Sprintf(apiURLHost+"/oauth/token"),
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch bearer token")
	}
	defer func() {
		if closeErr := res.Body.Close(); err == nil {
			err = closeErr
		}
	}()

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to fetch bearer token. status code: %v, response: %v",
			res.StatusCode,
			string(resBody),
		)
	}

	var bearerToken BearerToken
	if err = json.Unmarshal(resBody, &bearerToken); err != nil {
		return nil, err
	}

	return &bearerToken, err
}
