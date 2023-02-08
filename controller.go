package fake_kubelet

import (
	"context"
	"fmt"

	"github.com/wzshiming/fake-kubelet/metrics/collectors"
	"github.com/wzshiming/fake-kubelet/metrics/stats"
	"net"
	"net/http"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	compbasemetrics "k8s.io/component-base/metrics"
	"sigs.k8s.io/yaml"
)

var (
	startTime = time.Now().Format(time.RFC3339)

	funcMap = template.FuncMap{
		"Now": func() string {
			return time.Now().Format(time.RFC3339)
		},
		"StartTime": func() string {
			return startTime
		},
		"YAML": func(s interface{}, indent ...int) (string, error) {
			d, err := yaml.Marshal(s)
			if err != nil {
				return "", err
			}

			data := string(d)
			if len(indent) == 1 && indent[0] > 0 {
				pad := strings.Repeat(" ", indent[0]*2)
				data = strings.Replace("\n"+data, "\n", "\n"+pad, -1)
			}
			return data, nil
		},
	}
)

// Controller is a fake kubelet implementation that can be used to test
type Controller struct {
	nodes     *NodeController
	pods      *PodController
	providers *providerSets
}

type Config struct {
	ClientSet                         kubernetes.Interface
	TakeOverAll                       bool
	TakeOverLabelsSelector            string
	PodCustomStatusAnnotationSelector string
	CIDR                              string
	NodeIP                            string
	Logger                            Logger
	PodStatusTemplate                 string
	NodeTemplate                      string
	NodeInitializationTemplate        string
	NodeHeartbeatTemplate             string
}

type Logger interface {
	Printf(format string, v ...interface{})
}

// NewController creates a new fake kubelet controller
func NewController(conf Config, app string, group string) (*Controller, error) {
	var nodeSelectorFunc func(node *corev1.Node) bool
	var nodeLabelSelector string
	providers := newProviderSets()

	if conf.TakeOverAll {
		nodeSelectorFunc = func(node *corev1.Node) bool {
			return true
		}
	} else if group != "" {
		selector, err := labels.Parse("group=" + group)
		if err != nil {
			return nil, err
		}
		nodeSelectorFunc = func(node *corev1.Node) bool {
			if providers.Size() == 0 {
				return selector.Matches(labels.Set(node.Labels))
			} else {
				return providers.Has(node.Name)
			}
		}
		nodeLabelSelector = selector.String()
	} else if conf.TakeOverLabelsSelector != "" {
		selector, err := labels.Parse(conf.TakeOverLabelsSelector)
		if err != nil {
			return nil, err
		}
		nodeSelectorFunc = func(node *corev1.Node) bool {
			if providers.Size() == 0 {
				return selector.Matches(labels.Set(node.Labels))
			} else {
				return providers.Has(node.Name)
			}
		}
		nodeLabelSelector = selector.String()
	}

	var lockPodsOnNodeFunc func(ctx context.Context, nodeName string) error

	nodes, err := NewNodeController(NodeControllerConfig{
		ClientSet:         conf.ClientSet,
		NodeIP:            conf.NodeIP,
		NodeSelectorFunc:  nodeSelectorFunc,
		NodeLabelSelector: nodeLabelSelector,
		LockPodsOnNodeFunc: func(nodeName string) error {
			return lockPodsOnNodeFunc(context.Background(), nodeName)
		},
		GetDaemonPortFunc: func(nodeName string) string {
			node := providers.Get(nodeName)
			if node != nil {
				//conf.Logger.Printf("GetDaemonPortFunc nodeName: %s port: %d", nodeName, node.Port)
				return fmt.Sprintf("%d", node.Port)
			}
			return "0"
		},
		NodeTemplate:               conf.NodeTemplate,
		NodeInitializationTemplate: conf.NodeInitializationTemplate,
		NodeHeartbeatTemplate:      conf.NodeHeartbeatTemplate,
		NodeHeartbeatInterval:      30 * time.Second,
		NodeHeartbeatParallelism:   16,
		LockNodeParallelism:        16,
		Logger:                     conf.Logger,
		FuncMap:                    funcMap,
	}, app, group, providers)
	if err != nil {
		return nil, fmt.Errorf("failed to create nodes controller: %v", err)
	}

	pods, err := NewPodController(PodControllerConfig{
		ClientSet:                         conf.ClientSet,
		NodeIP:                            conf.NodeIP,
		CIDR:                              conf.CIDR,
		PodCustomStatusAnnotationSelector: conf.PodCustomStatusAnnotationSelector,
		PodStatusTemplate:                 conf.PodStatusTemplate,
		LockPodParallelism:                16,
		DeletePodParallelism:              16,
		NodeHasFunc:                       nodes.Has, // just handle pods that are on nodes we have
		Logger:                            conf.Logger,
		FuncMap:                           funcMap,
	}, providers)
	if err != nil {
		return nil, fmt.Errorf("failed to create pods controller: %v", err)
	}

	lockPodsOnNodeFunc = pods.LockPodsOnNode

	n := &Controller{
		pods:      pods,
		nodes:     nodes,
		providers: providers,
	}

	return n, nil
}

func (c *Controller) Start(ctx context.Context) error {
	err := c.pods.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start pods controller: %v", err)
	}
	err = c.nodes.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start nodes controller: %v", err)
	}

	go func() {
		t := time.NewTicker(10 * time.Second)
		for {
			<-t.C
			c.providers.Foreach(func(s string) {
				err = c.nodes.CreateNode(ctx, s)
				if err != nil {
					fmt.Printf("create node err:%v", err)
				}
			})
		}
	}()
	return nil
}

func (c *Controller) CreateNode(ctx context.Context, nodeName string, port int) error {
	provider := NewFakeNode(nodeName, port)
	c.providers.Put(nodeName, provider)

	go c.Metrics(ctx, provider, port)

	return c.nodes.CreateNode(ctx, nodeName)
}

func (c *Controller) Metrics(ctx context.Context, statsProvider stats.Provider, port int) {
	resourceRegistry := compbasemetrics.NewKubeRegistry()
	resourceRegistry.CustomMustRegister(collectors.NewResourceMetricsCollector(stats.NewResourceAnalyzer(statsProvider)))

	svc := &http.Server{
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
		Addr: fmt.Sprintf(":%d", port),
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			fmt.Printf("get url:%v %v\n", r.URL, r.RemoteAddr)
			switch r.URL.Path {
			case "/metrics/resource":
				handler := compbasemetrics.HandlerFor(resourceRegistry, compbasemetrics.HandlerOpts{ErrorHandling: compbasemetrics.ContinueOnError})
				handler.ServeHTTP(rw, r)
			default:
				http.NotFound(rw, r)
			}
		}),
	}

	err := svc.ListenAndServeTLS("./pki/kubelet-tls.crt", "./pki/kubelet-tls.key")
	if err != nil {
		fmt.Printf("fatal start server %d, err:%v", port, err)
	}
}
