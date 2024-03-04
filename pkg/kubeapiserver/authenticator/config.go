/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authenticator

import (
	"time"

	"github.com/go-openapi/spec"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authentication/group"
	"k8s.io/apiserver/pkg/authentication/request/anonymous"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/request/headerrequest"
	"k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/apiserver/pkg/authentication/request/websocket"
	"k8s.io/apiserver/pkg/authentication/request/x509"
	tokencache "k8s.io/apiserver/pkg/authentication/token/cache"
	"k8s.io/apiserver/pkg/authentication/token/tokenfile"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"

	// Initialize all known client auth plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/serviceaccount"
)

// Config contains the data on how to authenticate a request to the Kube API Server
type Config struct {
	Anonymous      bool
	BootstrapToken bool

	TokenAuthFile               string
	OIDCIssuerURL               string
	OIDCClientID                string
	OIDCCAFile                  string
	OIDCUsernameClaim           string
	OIDCUsernamePrefix          string
	OIDCGroupsClaim             string
	OIDCGroupsPrefix            string
	OIDCSigningAlgs             []string
	OIDCRequiredClaims          map[string]string
	ServiceAccountKeyFiles      []string
	ServiceAccountLookup        bool
	ServiceAccountIssuer        string
	APIAudiences                authenticator.Audiences
	WebhookTokenAuthnConfigFile string
	WebhookTokenAuthnVersion    string
	WebhookTokenAuthnCacheTTL   time.Duration

	TokenSuccessCacheTTL time.Duration
	TokenFailureCacheTTL time.Duration

	RequestHeaderConfig *authenticatorfactory.RequestHeaderConfig

	// TODO, this is the only non-serializable part of the entire config.  Factor it out into a clientconfig
	ServiceAccountTokenGetter   serviceaccount.ServiceAccountTokenGetter
	BootstrapTokenAuthenticator authenticator.Token
	// ClientCAContentProvider are the options for verifying incoming connections using mTLS and directly assigning to users.
	// Generally this is the CA bundle file used to authenticate client certificates
	// If this value is nil, then mutual TLS is disabled.
	ClientCAContentProvider dynamiccertificates.CAContentProvider

	// Optional field, custom dial function used to connect to webhook
	CustomDial utilnet.DialFunc
}

// New returns an authenticator.Request or an error that supports the standard
// Kubernetes authentication mechanisms.
func (config Config) New() (authenticator.Request, *spec.SecurityDefinitions, error) {
	// 关注这两个变量
	var authenticators []authenticator.Request
	var tokenAuthenticators []authenticator.Token
	securityDefinitions := spec.SecurityDefinitions{}

	// front-proxy, BasicAuth methods, local first, then remote
	// Add the front proxy authenticator if requested
	if config.RequestHeaderConfig != nil {
		// 添加 1. requestHeader
		requestHeaderAuthenticator := headerrequest.NewDynamicVerifyOptionsSecure(
			config.RequestHeaderConfig.CAContentProvider.VerifyOptions,
			config.RequestHeaderConfig.AllowedClientNames,
			config.RequestHeaderConfig.UsernameHeaders,
			config.RequestHeaderConfig.GroupHeaders,
			config.RequestHeaderConfig.ExtraHeaderPrefixes,
		)
		authenticators = append(authenticators, authenticator.WrapAudienceAgnosticRequest(config.APIAudiences, requestHeaderAuthenticator))
	}

	// X509 methods
	if config.ClientCAContentProvider != nil {
		// 2. 添加 ClientCA
		certAuth := x509.NewDynamic(config.ClientCAContentProvider.VerifyOptions, x509.CommonNameUserConversion)
		authenticators = append(authenticators, certAuth)
	}

	// Bearer token methods, local first, then remote
	if len(config.TokenAuthFile) > 0 {
		// 3. token 添加 token file
		tokenAuth, err := newAuthenticatorFromTokenFile(config.TokenAuthFile)
		if err != nil {
			return nil, nil, err
		}
		tokenAuthenticators = append(tokenAuthenticators, authenticator.WrapAudienceAgnosticToken(config.APIAudiences, tokenAuth))
	}

	// 4. token 添加 service account
	// 如果指定了 ServiceAccountKeyFiles，就添加 Legacy Service Account 认证器
	// 对应到 /etc/kubernetes/manifests/kube-apiserver.yaml中关于 apiserver 的启动参数中的
	// - --service-account-key-file=/etc/kubernetes/pki/sa.pub
	if len(config.ServiceAccountKeyFiles) > 0 {
		serviceAccountAuth, err := newLegacyServiceAccountAuthenticator(config.ServiceAccountKeyFiles, config.ServiceAccountLookup, config.APIAudiences, config.ServiceAccountTokenGetter)
		if err != nil {
			return nil, nil, err
		}
		tokenAuthenticators = append(tokenAuthenticators, serviceAccountAuth)
	}
	// 如果启用了 TokenRequest 特性并且指定了 ServiceAccountIssuer，就添加新的 Service Account 认证器
	// 对应到启动的命令的 - -- service-account-issuer=https://kubernetes.default.svc.cluster.local
	if utilfeature.DefaultFeatureGate.Enabled(features.TokenRequest) && config.ServiceAccountIssuer != "" {
		serviceAccountAuth, err := newServiceAccountAuthenticator(config.ServiceAccountIssuer, config.ServiceAccountKeyFiles, config.APIAudiences, config.ServiceAccountTokenGetter)
		if err != nil {
			return nil, nil, err
		}
		tokenAuthenticators = append(tokenAuthenticators, serviceAccountAuth)
	}

	if config.BootstrapToken {
		// 5. 添加 bootstrap
		if config.BootstrapTokenAuthenticator != nil {
			// TODO: This can sometimes be nil because of
			tokenAuthenticators = append(tokenAuthenticators, authenticator.WrapAudienceAgnosticToken(config.APIAudiences, config.BootstrapTokenAuthenticator))
		}
	}
	// NOTE(ericchiang): Keep the OpenID Connect after Service Accounts.
	//
	// Because both plugins verify JWTs whichever comes first in the union experiences
	// cache misses for all requests using the other. While the service account plugin
	// simply returns an error, the OpenID Connect plugin may query the provider to
	// update the keys, causing performance hits.
	// OIDC: OpenID Connect，建立在 OAuth2.0 协议上的一个身份验证和授权协议
	if len(config.OIDCIssuerURL) > 0 && len(config.OIDCClientID) > 0 {
		oidcAuth, err := newAuthenticatorFromOIDCIssuerURL(oidc.Options{
			IssuerURL:            config.OIDCIssuerURL,
			ClientID:             config.OIDCClientID,
			CAFile:               config.OIDCCAFile,
			UsernameClaim:        config.OIDCUsernameClaim,
			UsernamePrefix:       config.OIDCUsernamePrefix,
			GroupsClaim:          config.OIDCGroupsClaim,
			GroupsPrefix:         config.OIDCGroupsPrefix,
			SupportedSigningAlgs: config.OIDCSigningAlgs,
			RequiredClaims:       config.OIDCRequiredClaims,
		})
		if err != nil {
			return nil, nil, err
		}
		// 6. token 添加 oidc
		tokenAuthenticators = append(tokenAuthenticators, authenticator.WrapAudienceAgnosticToken(config.APIAudiences, oidcAuth))
	}
	if len(config.WebhookTokenAuthnConfigFile) > 0 {
		webhookTokenAuth, err := newWebhookTokenAuthenticator(config)
		if err != nil {
			return nil, nil, err
		}

		// 7. 添加 webhook
		tokenAuthenticators = append(tokenAuthenticators, webhookTokenAuth)
	}

	// 8. 合并 tokenAuthenticators 到 authenticators 中
	if len(tokenAuthenticators) > 0 {
		// Union the token authenticators
		tokenAuth := tokenunion.New(tokenAuthenticators...)
		// Optionally cache authentication results
		if config.TokenSuccessCacheTTL > 0 || config.TokenFailureCacheTTL > 0 {
			tokenAuth = tokencache.New(tokenAuth, true, config.TokenSuccessCacheTTL, config.TokenFailureCacheTTL)
		}
		authenticators = append(authenticators, bearertoken.New(tokenAuth), websocket.NewProtocolAuthenticator(tokenAuth))
		securityDefinitions["BearerToken"] = &spec.SecurityScheme{
			SecuritySchemeProps: spec.SecuritySchemeProps{
				Type:        "apiKey",
				Name:        "authorization",
				In:          "header",
				Description: "Bearer Token authentication",
			},
		}
	}

	// 9. 在没有任何的鉴权策略下，开启了匿名功能，就直接使用匿名功能；如果没开启，就报错
	if len(authenticators) == 0 {
		if config.Anonymous {
			return anonymous.NewAuthenticator(), &securityDefinitions, nil
		}
		return nil, &securityDefinitions, nil
	}

	// 10.合并authenticators
	// 这里可以看下，authenticators 是一个 authenticators.Request类型的切片，authenticator居然也是 Request 类型
	// 然后进入到 New 方法可以看到，我们返回的是一个 unionAuthRequestHandler，它的结构体里有Handlers []authenticator.Request
	// 所以它是和我们之前看的 kubectl 中 DecoratedVisitor 一样的，采用了装饰器设计模式
	authenticator := union.New(authenticators...)

	authenticator = group.NewAuthenticatedGroupAdder(authenticator)

	if config.Anonymous {
		// If the authenticator chain returns an error, return an error (don't consider a bad bearer token
		// or invalid username/password combination anonymous).
		authenticator = union.NewFailOnError(authenticator, anonymous.NewAuthenticator())
	}

	return authenticator, &securityDefinitions, nil
}

// IsValidServiceAccountKeyFile returns true if a valid public RSA key can be read from the given file
func IsValidServiceAccountKeyFile(file string) bool {
	_, err := keyutil.PublicKeysFromFile(file)
	return err == nil
}

// newAuthenticatorFromTokenFile returns an authenticator.Token or an error
func newAuthenticatorFromTokenFile(tokenAuthFile string) (authenticator.Token, error) {
	tokenAuthenticator, err := tokenfile.NewCSV(tokenAuthFile)
	if err != nil {
		return nil, err
	}

	return tokenAuthenticator, nil
}

// newAuthenticatorFromOIDCIssuerURL returns an authenticator.Token or an error.
func newAuthenticatorFromOIDCIssuerURL(opts oidc.Options) (authenticator.Token, error) {
	const noUsernamePrefix = "-"

	if opts.UsernamePrefix == "" && opts.UsernameClaim != "email" {
		// Old behavior. If a usernamePrefix isn't provided, prefix all claims other than "email"
		// with the issuerURL.
		//
		// See https://github.com/kubernetes/kubernetes/issues/31380
		opts.UsernamePrefix = opts.IssuerURL + "#"
	}

	if opts.UsernamePrefix == noUsernamePrefix {
		// Special value indicating usernames shouldn't be prefixed.
		opts.UsernamePrefix = ""
	}

	tokenAuthenticator, err := oidc.New(opts)
	if err != nil {
		return nil, err
	}

	return tokenAuthenticator, nil
}

// newLegacyServiceAccountAuthenticator returns an authenticator.Token or an error
func newLegacyServiceAccountAuthenticator(keyfiles []string, lookup bool, apiAudiences authenticator.Audiences, serviceAccountGetter serviceaccount.ServiceAccountTokenGetter) (authenticator.Token, error) {
	allPublicKeys := []interface{}{}
	for _, keyfile := range keyfiles {
		publicKeys, err := keyutil.PublicKeysFromFile(keyfile)
		if err != nil {
			return nil, err
		}
		allPublicKeys = append(allPublicKeys, publicKeys...)
	}

	tokenAuthenticator := serviceaccount.JWTTokenAuthenticator(serviceaccount.LegacyIssuer, allPublicKeys, apiAudiences, serviceaccount.NewLegacyValidator(lookup, serviceAccountGetter))
	return tokenAuthenticator, nil
}

// newServiceAccountAuthenticator returns an authenticator.Token or an error
func newServiceAccountAuthenticator(iss string, keyfiles []string, apiAudiences authenticator.Audiences, serviceAccountGetter serviceaccount.ServiceAccountTokenGetter) (authenticator.Token, error) {
	allPublicKeys := []interface{}{}
	for _, keyfile := range keyfiles {
		publicKeys, err := keyutil.PublicKeysFromFile(keyfile)
		if err != nil {
			return nil, err
		}
		allPublicKeys = append(allPublicKeys, publicKeys...)
	}

	tokenAuthenticator := serviceaccount.JWTTokenAuthenticator(iss, allPublicKeys, apiAudiences, serviceaccount.NewValidator(serviceAccountGetter))
	return tokenAuthenticator, nil
}

func newWebhookTokenAuthenticator(config Config) (authenticator.Token, error) {
	webhookTokenAuthenticator, err := webhook.New(config.WebhookTokenAuthnConfigFile, config.WebhookTokenAuthnVersion, config.APIAudiences, config.CustomDial)
	if err != nil {
		return nil, err
	}

	return tokencache.New(webhookTokenAuthenticator, false, config.WebhookTokenAuthnCacheTTL, config.WebhookTokenAuthnCacheTTL), nil
}
