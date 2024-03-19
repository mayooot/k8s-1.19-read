/*
Copyright 2019 The Kubernetes Authors.

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

package nodename

import (
	"context"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	framework "k8s.io/kubernetes/pkg/scheduler/framework/v1alpha1"
)

// NodeName is a plugin that checks if a pod spec node name matches the current node.
type NodeName struct{}

var _ framework.FilterPlugin = &NodeName{}

// 调度算法的名称和错误信息
const (
	// Name is the name of the plugin used in the plugin registry and configurations.
	Name = "NodeName"

	// ErrReason returned when node name doesn't match.
	ErrReason = "node(s) didn't match the requested hostname"
)

// Name returns name of the plugin. It is used in logs, etc.
func (pl *NodeName) Name() string {
	return Name
}

// Filter invoked at the filter extension point.
// 过滤功能，NodeName 算法的实现
func (pl *NodeName) Filter(ctx context.Context, _ *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	if nodeInfo.Node() == nil {
		return framework.NewStatus(framework.Error, "node not found")
	}
	// 匹配 pod.Spec.NodeName 和 nodeInfo.Node().Name
	if !Fits(pod, nodeInfo) {
		return framework.NewStatus(framework.UnschedulableAndUnresolvable, ErrReason)
	}
	return nil
}

// Fits actually checks if the pod fits the node.
// 满足任何一个条件就会成功
// 1. pod.Spec.NodeName 为空
// 2. pod 的 NodeName 和节点的匹配
func Fits(pod *v1.Pod, nodeInfo *framework.NodeInfo) bool {
	return len(pod.Spec.NodeName) == 0 || pod.Spec.NodeName == nodeInfo.Node().Name
}

// New initializes a new plugin and returns it.
// 初始化
func New(_ runtime.Object, _ framework.FrameworkHandle) (framework.Plugin, error) {
	return &NodeName{}, nil
}
