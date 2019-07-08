package auth0

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

const (
	AuthZeroHost     = "auth0.com"
	AuthorizationKey = "Authorization"
)

type (
	UserInfo struct {
		ID         string      `json:"user_id"`
		Oid        string      `json:"oid"`
		Identities []*Identity `json:"identities"`
		Name       string      `json:"name"`
		Email      string      `json:"email"`
		FamilyName string      `json:"family_name"`
		GivenName  string      `json:"given_name"`
		Nickname   string      `json:"nickname"`
	}

	Identity struct {
		UserID   string `json:"user_id"`
		Provider string `json:"provider"`
	}

	User struct {
		FederatedID      string
		AggregatorID     string
		Name             string
		Email            string
		FamilyName       string
		GivenName        string
		Nickname         string
		IdentityProvider string
	}

	Client interface {
		GetUser(userID string) (*User, error)
		GetAllUsers() ([]*User, error)
		GetBearerToken() (*BearerToken, error)
		GetUsersByRole(role string) ([]*User, error)
	}

	authZeroClient struct {
		clientID     string
		clientSecret string
		audience     string
		auth0Service Service
		apiURL       string
	}
)

func NewClient(clientID, clientSecret, audience, tenant string) Client {
	host := fmt.Sprintf("https://%v.%v", tenant, AuthZeroHost)

	return &authZeroClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		audience:     audience,
		apiURL:       fmt.Sprintf("%v/api/v2", host),
		auth0Service: NewService(tenant, host),
	}
}

func (client *authZeroClient) GetBearerToken() (*BearerToken, error) {
	return client.auth0Service.GetBearerToken(client.audience, client.clientID, client.clientSecret)
}

func (client *authZeroClient) GetUser(userID string) (*User, error) {
	bearerToken, err := client.GetBearerToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get bearer token")
	}

	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%v/users/%v", client.apiURL, userID),
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create get request")
	}

	req.Header.Add("authorization", fmt.Sprintf("%v %v", bearerToken.TokenType, bearerToken.AccessToken))

	httpClient := &http.Client{}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch user")
	}
	defer func() {
		if closeErr := res.Body.Close(); err == nil {
			err = closeErr
		}
	}()

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to fetch user. status code: %v, response: %v",
			res.StatusCode,
			string(resBody),
		)
	}

	var user UserInfo
	err = json.Unmarshal(resBody, &user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to deserialise user")
	}

	return user.toUser(), err
}

func (client *authZeroClient) GetUsersByRole(role string) ([]*User, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf(
			"%v/users?fields=user_id,name&q=app_metadata.groups:'%s'",
			client.apiURL,
			role,
		),
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a new http request")
	}

	auth0Service, err := client.auth0Service.GetBearerToken(
		client.audience,
		client.clientID,
		client.clientSecret,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get bearer token")
	}

	req.Header.Add(AuthorizationKey, fmt.Sprintf("Bearer %s", auth0Service.AccessToken))

	httpClient := &http.Client{}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch users by role")
	}
	defer func() {
		if closeErr := res.Body.Close(); err == nil {
			err = closeErr
		}
	}()

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to fetch users by role, status not OK. status code: %v, response: %v",
			res.StatusCode,
			string(resBody),
		)
	}

	var users []*UserInfo
	err = json.Unmarshal(resBody, &users)
	if err != nil {
		return nil, errors.Wrap(err, "failed to deserialise users")
	}

	return toUsers(users), err
}

func (client *authZeroClient) GetAllUsers() ([]*User, error) {
	page := 0
	pageLimit := 50
	returned := pageLimit
	allUsers := []*User{}
	for returned == pageLimit {
		users, err := client.getAllUsers(page, pageLimit)
		if err != nil {
			return nil, err
		}
		returned = len(users)
		page++
		allUsers = append(allUsers, users...)
	}

	return allUsers, nil
}

func (client *authZeroClient) getAllUsers(page, pageLimit int) ([]*User, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%v/users?per_page=%v&page=%v", client.apiURL, pageLimit, page),
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a new http request")
	}

	bearerToken, err := client.GetBearerToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get bearer token")
	}

	req.Header.Add(AuthorizationKey, fmt.Sprintf("Bearer %s", bearerToken.AccessToken))

	httpClient := &http.Client{}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch all users")
	}
	defer func() {
		if closeErr := res.Body.Close(); err == nil {
			err = closeErr
		}
	}()

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read body")
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to fetch all users, status not OK. status code: %v, response: %v",
			res.StatusCode,
			string(resBody),
		)
	}

	var users []*UserInfo
	err = json.Unmarshal(resBody, &users)
	if err != nil {
		return nil, errors.Wrap(err, "failed to deserialise user")
	}

	return toUsers(users), err
}

func toUsers(infos []*UserInfo) []*User {
	users := make([]*User, len(infos))

	for i, info := range infos {
		users[i] = info.toUser()
	}

	return users
}

func (userInfo *UserInfo) toUser() *User {
	user := &User{
		AggregatorID:     userInfo.ID,
		Name:             userInfo.Name,
		Email:            userInfo.Email,
		FamilyName:       userInfo.FamilyName,
		GivenName:        userInfo.GivenName,
		Nickname:         userInfo.Nickname,
		IdentityProvider: userInfo.Identities[0].Provider,
	}

	if len(userInfo.Oid) > 0 {
		user.FederatedID = userInfo.Oid
	} else {
		user.FederatedID = userInfo.Identities[0].UserID
	}

	return user
}
