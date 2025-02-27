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

package stats

// ResourceAnalyzer provides statistics on node resource consumption
type ResourceAnalyzer interface {
	Start()

	SummaryProvider
}

// resourceAnalyzer implements ResourceAnalyzer
type resourceAnalyzer struct {
	SummaryProvider
}

var _ ResourceAnalyzer = &resourceAnalyzer{}

// NewResourceAnalyzer returns a new ResourceAnalyzer
func NewResourceAnalyzer(statsProvider Provider) ResourceAnalyzer {
	summaryProvider := NewSummaryProvider(statsProvider)
	return &resourceAnalyzer{summaryProvider}
}

// Start starts background functions necessary for the ResourceAnalyzer to function
func (ra *resourceAnalyzer) Start() {
}
