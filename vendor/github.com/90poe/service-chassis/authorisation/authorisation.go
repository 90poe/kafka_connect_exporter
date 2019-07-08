package authorisation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	jwt "github.com/gbrlsnchs/jwt/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

type (
	BearerToken struct {
		bearerToken     string
		serviceTokenJwt string
	}

	contextKey int

	ServiceToken struct {
		*jwt.JWT
		Account      string
		AccountRoles []string
		Permissions  []string
		UserID       string
		Application  string
		Context      string
	}

	GetPublicKey func(keyID string) (*rsa.PublicKey, error)

	AccessLevelOperator int
	AccessLevel         rune
	AccessLevels        []AccessLevel

	Permission struct {
		ResourceName string
		AccessLevels AccessLevels
	}

	TokenIssuer interface {
		IssueNewServiceToken(user string, permissions []*Permission, roles []string, keyID string) (string, error)
	}

	tokenIssuer struct {
		expiry             time.Duration
		privateKey         *rsa.PrivateKey
		account            string
		application        string
		context            string
		serviceTokenIssuer string
		keyID              string
	}

	Context interface {
		HasAnyLevelAccessToResource(resourceName string) bool
		HasPermission(resourceName string, accessLevel AccessLevel) bool
		HasPermissions(resourceName string, operator AccessLevelOperator, accessLevels ...AccessLevel) bool
		HasRole(roles ...string) bool
	}

	authorisationContext struct {
		permissions map[string]*Permission
		roles       []string
	}
)

const (
	Read     AccessLevel = 'R'
	Update   AccessLevel = 'U'
	Download AccessLevel = 'N'
	Create   AccessLevel = 'C'
	Delete   AccessLevel = 'D'
	List     AccessLevel = 'L'

	All AccessLevelOperator = iota
	Any

	serviceTokenContextKey contextKey = iota
	authorisationContextContextKey
	serviceTokenJwtContextKey

	// AuthorizationPrefix is the bearer prefix
	authorizationPrefix = "Bearer "
)

var (
	errInvalidBearerToken = errors.New("Invalid bearer token")
)

func NewBearerToken(bearerToken string) (*BearerToken, error) {
	if len(bearerToken) > len(authorizationPrefix) && strings.HasPrefix(bearerToken, authorizationPrefix) {
		return &BearerToken{bearerToken: bearerToken, serviceTokenJwt: bearerToken[len(authorizationPrefix):]}, nil
	}

	return nil, errInvalidBearerToken
}

func (token *BearerToken) ServiceTokenJwt() string {
	return token.serviceTokenJwt
}

func (token *BearerToken) BearerToken() string {
	return token.bearerToken
}

func ParseBearerToken(bearerToken *BearerToken, verifyJwt bool, getPublicKey GetPublicKey) (serviceToken *ServiceToken, err error) {
	if verifyJwt {
		serviceToken, _, err = ParseAndVerify(bearerToken.serviceTokenJwt, getPublicKey)
	} else {
		serviceToken, _, err = Parse(bearerToken.serviceTokenJwt)
	}

	return
}

func SetAuthorisationContext(ctx context.Context, serviceToken *ServiceToken, serviceTokenJwt string) (context.Context, error) {
	authContext, err := NewAuthorisationContext(serviceToken.Permissions, serviceToken.AccountRoles)
	if err != nil {
		return ctx, err
	}

	ctx = SetServiceTokenJwt(ctx, serviceTokenJwt)
	ctx = SetServiceToken(ctx, serviceToken)
	return SetAuthContext(ctx, authContext), nil
}

func NewAuthorisationContext(permissions []string, roles []string) (Context, error) {
	parsedPerms, err := ParsePermissions(permissions)
	if err != nil {
		return nil, err
	}

	permMap := make(map[string]*Permission, len(parsedPerms))

	for _, permission := range parsedPerms {
		permMap[permission.ResourceName] = permission
	}

	return &authorisationContext{
		roles:       roles,
		permissions: permMap,
	}, nil
}

func (context *authorisationContext) HasAnyLevelAccessToResource(resourceName string) bool {
	_, ok := context.permissions[resourceName]
	return ok
}

func HasAnyLevelAccessToResource(ctx context.Context, resourceName string) bool {
	authContext, ok := GetAuthContext(ctx)
	if !ok {
		return false
	}

	return authContext.HasAnyLevelAccessToResource(resourceName)
}

func (context *authorisationContext) HasPermission(resourceName string, accessLevel AccessLevel) bool {
	permission, ok := context.permissions[resourceName]
	if !ok {
		return false
	}

	return permission.AccessLevels.Contains(accessLevel)
}

func HasPermission(ctx context.Context, resourceName string, accessLevel AccessLevel) bool {
	authContext, ok := GetAuthContext(ctx)
	if !ok {
		return false
	}

	return authContext.HasPermission(resourceName, accessLevel)
}

func (context *authorisationContext) HasPermissions(resourceName string, operator AccessLevelOperator, accessLevels ...AccessLevel) bool {
	return ContainsPermissions(context.permissions, resourceName, operator, accessLevels...)
}

func ContainsPermissions(permissions map[string]*Permission, resourceName string, operator AccessLevelOperator, accessLevels ...AccessLevel) bool {
	permission, ok := permissions[resourceName]
	if !ok {
		return false
	}

	accessLevelMatches := 0
	for _, accessLevel := range accessLevels {
		if !permission.AccessLevels.Contains(accessLevel) {
			if operator == All {
				return false
			}
		} else {
			accessLevelMatches++
			if operator == Any {
				return true
			}
		}
	}

	return len(accessLevels) == accessLevelMatches
}

func HasPermissions(ctx context.Context, resourceName string, operator AccessLevelOperator, accessLevels ...AccessLevel) bool {
	authContext, ok := GetAuthContext(ctx)
	if !ok {
		return false
	}

	return authContext.HasPermissions(resourceName, operator, accessLevels...)
}

func (context *authorisationContext) HasRole(roles ...string) bool {
	for _, role := range roles {
		for _, contextRole := range context.roles {
			if role == contextRole {
				return true
			}
		}
	}

	return false
}

func HasRole(ctx context.Context, roles ...string) bool {
	authContext, ok := GetAuthContext(ctx)
	if !ok {
		return false
	}

	return authContext.HasRole(roles...)
}

func (accessLevels AccessLevels) Contains(accessLevel AccessLevel) bool {
	for _, level := range accessLevels {
		if level == accessLevel {
			return true
		}
	}

	return false
}

func ParsePermissions(perms []string) ([]*Permission, error) {
	permissions := make([]*Permission, len(perms))
	for i, perm := range perms {
		if permission, err := ParsePermission(perm); err == nil {
			permissions[i] = permission
		} else {
			return nil, err
		}
	}

	return permissions, nil
}

func SerialisePermissions(perms []*Permission) []string {
	permissions := make([]string, len(perms))
	for i, perm := range perms {
		permissions[i] = SerialisePermission(perm)
	}

	return permissions
}

func ParseAccessLevel(level string) (*AccessLevel, error) {

	switch strings.ToUpper(strings.Trim(level, " ")) {
	case "R":
		return accessLevelPointer(Read), nil
	case "U":
		return accessLevelPointer(Update), nil
	case "N":
		return accessLevelPointer(Download), nil
	case "C":
		return accessLevelPointer(Create), nil
	case "L":
		return accessLevelPointer(List), nil
	case "D":
		return accessLevelPointer(Delete), nil
	default:
		return nil, errors.New("Unrecognised access level string : " + level)
	}
}

func ParseAccessLevels(levels string) ([]AccessLevel, error) {
	lvls := make(AccessLevels, len(levels))
	for index, level := range levels {
		accessLevel, err := ParseAccessLevel(string(level))
		if err != nil {
			return nil, err
		}
		if lvls.Contains(*accessLevel) {
			return nil, fmt.Errorf("duplicate error level %v", accessLevel)
		}

		lvls[index] = *accessLevel
	}

	return lvls, nil
}

func accessLevelPointer(level AccessLevel) *AccessLevel {
	return &level
}

func ParsePermission(permission string) (*Permission, error) {
	parts := strings.Split(permission, ":")
	if len(parts) == 2 && !isEmptyOrWhiteSpace(parts[0]) && !isEmptyOrWhiteSpace(parts[1]) {

		levels, err := ParseAccessLevels(parts[1])
		if err != nil {
			return nil, err
		}
		for index, level := range parts[1] {
			accessLevel, err := ParseAccessLevel(string(level))
			if err != nil {
				return nil, err
			}
			levels[index] = *accessLevel
		}

		return &Permission{
			ResourceName: parts[0],
			AccessLevels: levels,
		}, nil
	}

	return nil, errors.New("Invalid permission string : " + permission)
}

func SerialisePermission(permission *Permission) string {
	perm := permission.ResourceName + ":"

	for _, char := range permission.AccessLevels {
		perm += string(char)
	}

	return perm
}

func isEmptyOrWhiteSpace(val string) bool {
	return len(strings.TrimSpace(val)) == 0
}

func parse(token string) (*ServiceToken, string, []byte, error) {
	payload, sig, err := jwt.Parse(token)
	if err != nil {
		return nil, "", nil, err
	}

	var serviceToken ServiceToken
	err = jwt.Unmarshal(payload, &serviceToken)

	return &serviceToken, string(payload), sig, err
}

func Parse(token string) (*ServiceToken, string, error) {
	serviceToken, payload, _, err := parse(token)
	return serviceToken, payload, err
}

func ParseAndVerify(token string, getPublicKey GetPublicKey) (*ServiceToken, string, error) {
	serviceToken, payload, sig, err := parse(token)
	if err != nil {
		return nil, "", err
	}

	now := time.Now().Unix()

	if serviceToken.NotBefore > now {
		return nil, "", errors.New("Token NotBefore is in the future")
	}

	if serviceToken.ExpirationTime < now {
		return nil, "", errors.New("Token has expired")
	}

	keyID := serviceToken.KeyID()
	if len(strings.Trim(keyID, " ")) == 0 {
		keyID = "key1" //temp hack
	}

	publicKey, err := getPublicKey(keyID)
	if err != nil {
		return nil, "", err
	}

	if err = jwt.NewRS256(nil, publicKey).Verify([]byte(payload), sig); err != nil {
		return nil, "", err
	}

	return serviceToken, payload, err
}

func (tokenIssuer *tokenIssuer) IssueNewServiceToken(user string, permissions []*Permission, roles []string, keyID string) (string, error) {
	if permissions == nil {
		permissions = []*Permission{}
	}

	if roles == nil {
		roles = []string{}
	}

	serviceToken := &ServiceToken{
		JWT: &jwt.JWT{
			IssuedAt:       time.Now().UTC().Unix(),
			Issuer:         tokenIssuer.serviceTokenIssuer,
			ExpirationTime: time.Now().UTC().Add(tokenIssuer.expiry).Unix(),
		},
		UserID:       user,
		Account:      tokenIssuer.account,
		Application:  tokenIssuer.application,
		Permissions:  SerialisePermissions(permissions),
		Context:      tokenIssuer.context,
		AccountRoles: roles,
	}

	rs256 := jwt.NewRS256(tokenIssuer.privateKey, nil)
	serviceToken.SetAlgorithm(rs256)
	serviceToken.SetKeyID(tokenIssuer.keyID)
	payload, err := jwt.Marshal(serviceToken)
	if err != nil {
		return "", nil
	}

	signedServiceToken, err := rs256.Sign(payload)
	if err != nil {
		return "", nil
	}

	return string(signedServiceToken), nil
}

func DefaultTokenIssuer() (TokenIssuer, *rsa.PrivateKey, error) {
	privateKey, _, err := CreateKey()
	if err != nil {
		return nil, nil, err
	}

	issuer, err := NewTokenIssuer("account", "application", "", "service-token-issuer", 5*time.Minute, privateKey)
	if err != nil {
		return nil, nil, err
	}

	return issuer, privateKey, nil
}

func NewTokenIssuer(account, application, context, serviceTokenIssuer string, expiry time.Duration, privateKey *rsa.PrivateKey) (TokenIssuer, error) {
	return &tokenIssuer{
		account:            account,
		expiry:             expiry,
		context:            context,
		application:        application,
		serviceTokenIssuer: serviceTokenIssuer,
		privateKey:         privateKey,
	}, nil
}

func CreateKey() (rsaPrivateKey *rsa.PrivateKey, jwkKey jwk.Key, err error) {
	if rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return
	}

	jwkKey, err = jwk.New(&rsaPrivateKey.PublicKey)

	return
}

func SetServiceTokenJwt(ctx context.Context, serviceTokenJwt string) context.Context {
	return context.WithValue(ctx, serviceTokenJwtContextKey, serviceTokenJwt)
}

func GetServiceTokenJwt(ctx context.Context) (string, bool) {
	serviceTokenJwt, ok := ctx.Value(serviceTokenJwtContextKey).(string)
	return serviceTokenJwt, ok
}

func SetServiceToken(ctx context.Context, serviceToken *ServiceToken) context.Context {
	return context.WithValue(ctx, serviceTokenContextKey, serviceToken)
}

func GetServiceToken(ctx context.Context) (*ServiceToken, bool) {
	serviceToken, ok := ctx.Value(serviceTokenContextKey).(*ServiceToken)
	return serviceToken, ok
}

func SetAuthContext(ctx context.Context, authContext Context) context.Context {
	return context.WithValue(ctx, authorisationContextContextKey, authContext)
}

func GetAuthContext(ctx context.Context) (Context, bool) {
	authContext, ok := ctx.Value(authorisationContextContextKey).(Context)
	return authContext, ok
}

func AddBearerTokenPrefix(jwtServiceToken string) string {
	return authorizationPrefix + jwtServiceToken
}
