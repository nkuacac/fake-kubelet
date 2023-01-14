package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	fake_kubelet "github.com/wzshiming/fake-kubelet"
	"github.com/wzshiming/fake-kubelet/templates"
	"github.com/wzshiming/notify"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"
)

var (
	cidr                              = getEnv("CIDR", "10.0.0.1/24")
	nodeIP                            = net.ParseIP(getEnv("NODE_IP", "196.168.0.1"))
	nodeName                          = getEnv("NODE_NAME", "fake")
	takeOverAll                       = getEnvBool("TAKE_OVER_ALL", false)
	takeOverLabelsSelector            = getEnv("TAKE_OVER_LABELS_SELECTOR", "type=fake-kubelet")
	podCustomStatusAnnotationSelector = getEnv("POD_CUSTOM_STATUS_ANNOTATION_SELECTOR", "fake=custom")
	generateNodeName                  = getEnv("GENERATE_NODE_NAME", "")
	generateReplicas                  = getEnvUint("GENERATE_REPLICAS", 0)
	generateSerialLength              = getEnvUint("GENERATE_SERIAL_LENGTH", 1)
	kubeconfig                        = getEnv("KUBECONFIG", "")
	healthAddress                     = getEnv("HEALTH_ADDRESS", "") // deprecated: use serverAddress instead
	serverAddress                     = getEnv("SERVER_ADDRESS", healthAddress)
	podStatusTemplatePath             = ""
	podStatusTemplate                 = getEnv("POD_STATUS_TEMPLATE", templates.DefaultPodStatusTemplate)
	nodeTemplatePath                  = ""
	nodeTemplate                      = getEnv("NODE_TEMPLATE", templates.DefaultNodeTemplate)
	nodeHeartbeatTemplateePath        = ""
	nodeHeartbeatTemplate             = getEnv("NODE_HEARTBEAT_TEMPLATE", templates.DefaultNodeHeartbeatTemplate)
	nodeInitializationTemplatePath    = ""
	nodeInitializationTemplate        = getEnv("NODE_INITIALIZATION_TEMPLATE", templates.DefaultNodeInitializationTemplate)
	master                            = ""

	logger = log.New(os.Stderr, "[fake-kubelet] ", log.LstdFlags)
)

func init() {
	compatibleFlags()
	pflag.StringVar(&cidr, "cidr", cidr, "CIDR of the pod ip")
	pflag.IPVar(&nodeIP, "node-ip", nodeIP, "IP of the node")
	pflag.StringVarP(&nodeName, "node-name", "n", nodeName, "Names of the node")
	pflag.BoolVar(&takeOverAll, "take-over-all", takeOverAll, "Take over all nodes, there should be no nodes maintained by real Kubelet in the cluster")
	pflag.StringVar(&takeOverLabelsSelector, "take-over-labels-selector", takeOverLabelsSelector, "Selector of nodes to take over")
	pflag.StringVar(&podCustomStatusAnnotationSelector, "pod-custom-status-annotation-selector", podCustomStatusAnnotationSelector, "Selector of pods that with this annotation will no longer maintain status and will be left to others to modify it")
	pflag.StringVar(&generateNodeName, "generate-node-name", generateNodeName, "Generate node name")
	pflag.UintVar(&generateReplicas, "generate-replicas", generateReplicas, "Generate replicas")
	pflag.UintVar(&generateSerialLength, "generate-serial-length", generateSerialLength, "Generate serial length")
	pflag.StringVar(&kubeconfig, "kubeconfig", kubeconfig, "Path to the kubeconfig file to use")
	pflag.StringVar(&master, "master", master, "Server is the address of the kubernetes cluster")
	pflag.StringVar(&serverAddress, "server-address", serverAddress, "Address to expose health and metrics on")
	pflag.StringVar(&podStatusTemplatePath, "pod-status-template-file", podStatusTemplatePath, "Template for pod status file")
	pflag.StringVar(&nodeTemplatePath, "node-template-file", nodeTemplatePath, "Template for node status file")
	pflag.StringVar(&nodeHeartbeatTemplateePath, "node-heartbeat-template-file", nodeHeartbeatTemplateePath, "Template for node heartbeat status file")
	pflag.StringVar(&nodeInitializationTemplatePath, "node-initialization-template-file", nodeInitializationTemplatePath, "Template for node initialization status file")

	pflag.Parse()

}

func readFile(path string, defaultContent string) (string, error) {
	if path == "" {
		return defaultContent, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return defaultContent, nil
	}
	return string(data), nil
}

// compatibleFlags is used to convert deprecated flags to new flags.
func compatibleFlags() {
	args := make([]string, 0, len(os.Args))
	args = append(args, os.Args[0])
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--") && strings.Contains(arg, "_") {
			newArg := strings.ReplaceAll(arg, "_", "-")
			fmt.Fprintf(os.Stderr, "WARNING: flag %q is deprecated, please use %q instead\n", arg, newArg)
			arg = newArg
		}
		args = append(args, arg)
	}
	os.Args = args
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	notify.OnceSlice([]os.Signal{syscall.SIGINT, syscall.SIGTERM}, cancel)

	var err error
	if kubeconfig != "" {
		f, err := os.Stat(kubeconfig)
		if err != nil || f.IsDir() {
			kubeconfig = ""
		}
	}

	podStatusTemplate, err = readFile(podStatusTemplatePath, podStatusTemplate)
	if err != nil {
		logger.Fatalf("Failed to read pod status template: %v", err)
	}
	nodeTemplate, err = readFile(nodeTemplatePath, nodeTemplate)
	if err != nil {
		logger.Fatalf("Failed to read node status template: %v", err)
	}
	nodeHeartbeatTemplate, err = readFile(nodeHeartbeatTemplateePath, nodeHeartbeatTemplate)
	if err != nil {
		logger.Fatalf("Failed to read node heartbeat template: %v", err)
	}
	nodeInitializationTemplate, err = readFile(nodeInitializationTemplatePath, nodeInitializationTemplate)
	if err != nil {
		logger.Fatalf("Failed to read node initialization template: %v", err)
	}

	clientset, err := newClientset(master, kubeconfig)
	if err != nil {
		logger.Fatalln(err)
	}

	if takeOverAll {
		logger.Printf("Watch all nodes")
	} else if takeOverLabelsSelector != "" {
		logger.Printf("Watch nodes with labels %q", takeOverLabelsSelector)
	}

	backoff := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0.1,
		Steps:    5,
	}
	err = wait.ExponentialBackoffWithContext(ctx, backoff,
		func() (bool, error) {
			_, err := clientset.CoreV1().Nodes().List(ctx,
				metav1.ListOptions{
					Limit: 1,
				})
			if err != nil {
				logger.Printf("Failed to list nodes: %v", err)
				return false, nil
			}
			return true, nil
		},
	)
	if err != nil {
		logger.Fatalf("Failed to list nodes: %v", err)
	}

	controller, err := fake_kubelet.NewController(fake_kubelet.Config{
		ClientSet:                         clientset,
		TakeOverAll:                       takeOverAll,
		TakeOverLabelsSelector:            takeOverLabelsSelector,
		PodCustomStatusAnnotationSelector: podCustomStatusAnnotationSelector,
		CIDR:                              cidr,
		NodeIP:                            nodeIP.String(),
		Logger:                            logger,
		PodStatusTemplate:                 podStatusTemplate,
		NodeTemplate:                      nodeTemplate,
		NodeHeartbeatTemplate:             nodeHeartbeatTemplate,
		NodeInitializationTemplate:        nodeInitializationTemplate,
	})
	if err != nil {
		logger.Fatalln(err)
	}

	if serverAddress != "" {
		go Server(ctx, serverAddress)
	}

	err = controller.Start(ctx)
	if err != nil {
		logger.Fatalln(err)
	}

	go func() {
		for _, n := range strings.SplitN(nodeName, ",", -1) {
			if n != "" {
				err = controller.CreateNode(ctx, n, 0)
				if err != nil {
					logger.Printf("Failed create node %q: %v", n, err)
				}
			}
		}
		if generateNodeName != "" {
			fake_kubelet.GenerateSerialNumber(int(generateReplicas), int(generateSerialLength), func(s string, port int) bool {
				name := generateNodeName + s
				err = controller.CreateNode(ctx, generateNodeName+s, port)
				if err != nil {
					logger.Printf("Failed create node %q: %v", name, err)
					return false
				}
				return true
			})
		}
	}()

	<-ctx.Done()
}

func Server(ctx context.Context, address string) {
	promHandler := promhttp.Handler()
	svc := &http.Server{
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
		Addr: address,
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/healthz", "/health":
				rw.Write([]byte("health"))
			case "/metrics":
				promHandler.ServeHTTP(rw, r)
			default:
				http.NotFound(rw, r)
			}
		}),
	}

	err := svc.ListenAndServe()
	if err != nil {
		logger.Fatal("Fatal start server")
	}
}

func newClientset(master, kubeconfig string) (kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		return nil, err
	}
	err = setConfigDefaults(cfg)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func setConfigDefaults(config *rest.Config) error {
	config.RateLimiter = flowcontrol.NewFakeAlwaysRateLimiter()
	return rest.SetKubernetesDefaults(config)
}

func getEnv(name string, defaults string) string {
	val, ok := os.LookupEnv(name)
	if ok {
		return val
	}
	return defaults
}

func getEnvBool(name string, defaults bool) bool {
	val, ok := os.LookupEnv(name)
	if ok {
		boolean, err := strconv.ParseBool(val)
		if err == nil {
			return boolean
		}
	}
	return defaults
}

func getEnvUint(name string, defaults uint) uint {
	val, ok := os.LookupEnv(name)
	if ok {
		num, err := strconv.ParseUint(val, 10, 64)
		if err == nil {
			return uint(num)
		}
	}
	return defaults
}
