package authorisation

import (
	"context"
	"time"

	"github.com/90poe/service-chassis/auth0"
	jwt "github.com/gbrlsnchs/jwt/v2"
	cache "github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

const (
	tokenKey = "serviceToken"
	// cache expiry = token expiry minus this value so that clients have a window for use before token expiry
	defaultTokenUsageWindow = 30 * time.Second
)

type (
	ServiceTokenService interface {
		GetServiceToken(ctx context.Context) (string, error)
	}

	Service interface {
		GetServiceToken(ctx context.Context, idToken string) (*RawServiceToken, error)
	}

	RawServiceToken struct {
		ServiceToken string
		ExpiresIn    int64
	}

	GetServiceTokenFunc func(ctx context.Context, idToken string) (string, error)

	authorisationService struct {
		getServiceToken GetServiceTokenFunc
	}

	cachedServiceTokenService struct {
		auth0Service            auth0.Service
		audience                string
		clientID                string
		clientSecret            string
		authorisationService    Service
		cache                   *cache.Cache
		usageTokenWindowSeconds time.Duration
	}
)

func NewServiceTokenService(auth0Service auth0.Service, audience, clientID,
	clientSecret string, authorisationService Service) ServiceTokenService {

	return &cachedServiceTokenService{
		auth0Service:            auth0Service,
		authorisationService:    authorisationService,
		audience:                audience,
		clientID:                clientID,
		clientSecret:            clientSecret,
		cache:                   cache.New(5*time.Minute, 10*time.Minute),
		usageTokenWindowSeconds: defaultTokenUsageWindow,
	}
}

func (service *cachedServiceTokenService) GetServiceToken(ctx context.Context) (string, error) {
	if serviceToken, ok := service.cache.Get(tokenKey); ok {
		return serviceToken.(*RawServiceToken).ServiceToken, nil
	}

	bearerToken, err := service.auth0Service.GetBearerToken(service.audience, service.clientID, service.clientSecret)
	if err != nil {
		return "", errors.Wrap(err, "failed to get bearer token")
	}

	serviceToken, err := service.authorisationService.GetServiceToken(ctx, bearerToken.AccessToken)
	if err != nil {
		return "", errors.Wrap(err, "failed to get service token")
	}

	cacheExpiry := (time.Second * time.Duration(serviceToken.ExpiresIn)) - service.usageTokenWindowSeconds
	if cacheExpiry > 0 {
		service.cache.Set(tokenKey, serviceToken, cacheExpiry)
	}

	return serviceToken.ServiceToken, nil
}

func NewAuthorisationService(getServiceTokenFunc GetServiceTokenFunc) Service {
	return &authorisationService{getServiceToken: getServiceTokenFunc}
}

func (service *authorisationService) GetServiceToken(ctx context.Context, idToken string) (*RawServiceToken, error) {
	serviceToken, err := service.getServiceToken(ctx, idToken)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get service token")
	}
	expiresIn, err := getExpiresIn(serviceToken)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get expires in")
	}
	return &RawServiceToken{ServiceToken: serviceToken, ExpiresIn: expiresIn}, nil
}

func getExpiresIn(token string) (int64, error) {
	payload, _, err := jwt.Parse(token)
	if err != nil {
		return 0, errors.Wrap(err, "failed to parse token")
	}
	var jot *jwt.JWT
	if err = jwt.Unmarshal(payload, &jot); err != nil {
		return 0, errors.Wrap(err, "failed to unmarshal token")
	}
	expiresIn := time.Until(time.Unix(jot.ExpirationTime, 0))
	return int64(expiresIn.Seconds()), nil
}
