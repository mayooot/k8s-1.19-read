/*
Copyright 2016 The Kubernetes Authors.

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

package authorizer

import (
	"fmt"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/apiserver/plugin/pkg/authorizer/webhook"
	versionedinformers "k8s.io/client-go/informers"
	"k8s.io/kubernetes/pkg/auth/authorizer/abac"
	"k8s.io/kubernetes/pkg/auth/nodeidentifier"
	"k8s.io/kubernetes/pkg/kubeapiserver/authorizer/modes"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/node"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"
)

// Config contains the data on how to authorize a request to the Kube API Server
type Config struct {
	AuthorizationModes []string

	// Options for ModeABAC

	// Path to an ABAC policy file.
	PolicyFile string

	// Options for ModeWebhook

	// Kubeconfig file for Webhook authorization plugin.
	WebhookConfigFile string
	// API version of subject access reviews to send to the webhook (e.g. "v1", "v1beta1")
	WebhookVersion string
	// TTL for caching of authorized responses from the webhook server.
	WebhookCacheAuthorizedTTL time.Duration
	// TTL for caching of unauthorized responses from the webhook server.
	WebhookCacheUnauthorizedTTL time.Duration

	VersionedInformerFactory versionedinformers.SharedInformerFactory

	// Optional field, custom dial function used to connect to webhook
	CustomDial utilnet.DialFunc
}

// New returns the right sort of union of multiple authorizer.Authorizer objects
// based on the authorizationMode or an error.
func (config Config) New() (authorizer.Authorizer, authorizer.RuleResolver, error) {
	// 必须传入一个授权的模式，RBAC、ABAC
	if len(config.AuthorizationModes) == 0 {
		return nil, nil, fmt.Errorf("at least one authorization mode must be passed")
	}

	var (
		// Authorizer: 通过调用 Attributes 接口的 0 个或者多个方法做出授权决定
		// 当授权成功返回 nil，否则返回 error
		authorizers []authorizer.Authorizer
		// RuleResolver: 提供一种机制，用于解析适用于特定用户在命名空间内的规则列表。
		ruleResolvers []authorizer.RuleResolver
	)

	// 这里通过一个 for 循环遍历 config.AuthorizationModes
	// 对应到真实的 K8s api-server 启动命令参数就是
	// - --authorization-mode=Node,RBAC
	// 可以看到这里使用了 Node、RBAC 两种
	for _, authorizationMode := range config.AuthorizationModes {
		// Keep cases in sync with constant list in k8s.io/kubernetes/pkg/kubeapiserver/authorizer/modes/modes.go.
		switch authorizationMode {
		case modes.ModeNode:
			graph := node.NewGraph()
			node.AddGraphEventHandlers(
				graph,
				config.VersionedInformerFactory.Core().V1().Nodes(),
				config.VersionedInformerFactory.Core().V1().Pods(),
				config.VersionedInformerFactory.Core().V1().PersistentVolumes(),
				config.VersionedInformerFactory.Storage().V1().VolumeAttachments(),
			)
			nodeAuthorizer := node.NewAuthorizer(graph, nodeidentifier.NewDefaultNodeIdentifier(), bootstrappolicy.NodeRules())
			authorizers = append(authorizers, nodeAuthorizer)
			ruleResolvers = append(ruleResolvers, nodeAuthorizer)

		case modes.ModeAlwaysAllow:
			alwaysAllowAuthorizer := authorizerfactory.NewAlwaysAllowAuthorizer()
			authorizers = append(authorizers, alwaysAllowAuthorizer)
			ruleResolvers = append(ruleResolvers, alwaysAllowAuthorizer)
		case modes.ModeAlwaysDeny:
			alwaysDenyAuthorizer := authorizerfactory.NewAlwaysDenyAuthorizer()
			authorizers = append(authorizers, alwaysDenyAuthorizer)
			ruleResolvers = append(ruleResolvers, alwaysDenyAuthorizer)
		case modes.ModeABAC:
			abacAuthorizer, err := abac.NewFromFile(config.PolicyFile)
			if err != nil {
				return nil, nil, err
			}
			authorizers = append(authorizers, abacAuthorizer)
			ruleResolvers = append(ruleResolvers, abacAuthorizer)
		case modes.ModeWebhook:
			webhookAuthorizer, err := webhook.New(config.WebhookConfigFile,
				config.WebhookVersion,
				config.WebhookCacheAuthorizedTTL,
				config.WebhookCacheUnauthorizedTTL,
				config.CustomDial)
			if err != nil {
				return nil, nil, err
			}
			authorizers = append(authorizers, webhookAuthorizer)
			ruleResolvers = append(ruleResolvers, webhookAuthorizer)
		case modes.ModeRBAC:
			rbacAuthorizer := rbac.New(
				&rbac.RoleGetter{Lister: config.VersionedInformerFactory.Rbac().V1().Roles().Lister()},
				&rbac.RoleBindingLister{Lister: config.VersionedInformerFactory.Rbac().V1().RoleBindings().Lister()},
				&rbac.ClusterRoleGetter{Lister: config.VersionedInformerFactory.Rbac().V1().ClusterRoles().Lister()},
				&rbac.ClusterRoleBindingLister{Lister: config.VersionedInformerFactory.Rbac().V1().ClusterRoleBindings().Lister()},
			)
			// 这里可以将rbacAuthorizer添加到两个切片，是因为它实现了 Authorizer 和 RuleResolver 两个接口
			authorizers = append(authorizers, rbacAuthorizer)
			ruleResolvers = append(ruleResolvers, rbacAuthorizer)
		default:
			return nil, nil, fmt.Errorf("unknown authorization mode %s specified", authorizationMode)
		}
	}

	// 这里authorizers和ruleResolvers都是切片，里面有多个对象
	// 注意这里的 union.New和union.NewRuleResolvers，首先它们的返回值都是authorizer.Authorizer interface
	// 不同的是，这里用过了 装饰器设计模式和 golang 的类型定义
	// type unionAuthzHandler []authorizer.Authorizer，然后实现了 interface 定义的 Authorize 方法
	// 方法的实现是对 chain 的调用
	return union.New(authorizers...), union.NewRuleResolvers(ruleResolvers...), nil
}
