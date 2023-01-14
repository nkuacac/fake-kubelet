package fake_kubelet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"
)

var (
	removeFinalizers = []byte(`{"metadata":{"finalizers":null}}`)
	deleteOpt        = *metav1.NewDeleteOptions(0)
	podFieldSelector = fields.OneTermNotEqualSelector("spec.nodeName", "").String()
)

// PodController is a fake pods implementation that can be used to test
type PodController struct {
	clientSet                         kubernetes.Interface
	podCustomStatusAnnotationSelector labels.Selector
	nodeIP                            string
	cidrIPNet                         *net.IPNet
	nodeHasFunc                       func(nodeName string) bool
	ipPool                            *ipPool
	podStatusTemplate                 string
	logger                            Logger
	funcMap                           template.FuncMap
	lockPodChan                       chan *corev1.Pod
	lockPodParallelism                int
	deletePodChan                     chan *corev1.Pod
	deletePodParallelism              int
	providers                         *providerSets
}

// PodControllerConfig is the configuration for the PodController
type PodControllerConfig struct {
	ClientSet                         kubernetes.Interface
	PodCustomStatusAnnotationSelector string
	NodeIP                            string
	CIDR                              string
	NodeHasFunc                       func(nodeName string) bool
	PodStatusTemplate                 string
	Logger                            Logger
	LockPodParallelism                int
	DeletePodParallelism              int
	FuncMap                           template.FuncMap
}

// NewPodController creates a new fake pods controller
func NewPodController(conf PodControllerConfig, sets *providerSets) (*PodController, error) {
	cidrIPNet, err := parseCIDR(conf.CIDR)
	if err != nil {
		return nil, err
	}

	podCustomStatusAnnotationSelector, err := labels.Parse(conf.PodCustomStatusAnnotationSelector)
	if err != nil {
		return nil, err
	}

	n := &PodController{
		clientSet:                         conf.ClientSet,
		podCustomStatusAnnotationSelector: podCustomStatusAnnotationSelector,
		nodeIP:                            conf.NodeIP,
		cidrIPNet:                         cidrIPNet,
		ipPool:                            newIPPool(cidrIPNet),
		nodeHasFunc:                       conf.NodeHasFunc,
		logger:                            conf.Logger,
		podStatusTemplate:                 conf.PodStatusTemplate,
		lockPodChan:                       make(chan *corev1.Pod),
		lockPodParallelism:                conf.LockPodParallelism,
		deletePodChan:                     make(chan *corev1.Pod),
		deletePodParallelism:              conf.DeletePodParallelism,
		providers:                         sets,
	}
	n.funcMap = template.FuncMap{
		"NodeIP": func() string {
			return n.nodeIP
		},
		"PodIP": func() string {
			return n.ipPool.Get()
		},
		"Finish": func(in map[string]interface{}, key string, schedule string) bool {
			pod := metav1.ObjectMeta{}
			marshal, _ := json.Marshal(in["metadata"])
			e := json.Unmarshal(marshal, &pod)
			if e != nil {
				return false
			}
			start := metav1.Time{}
			e = json.Unmarshal([]byte(schedule), &start)
			if e != nil {
				return false
			}
			success := pod.Annotations[key]
			duration, e := time.ParseDuration(success)
			if e == nil && time.Since(start.Add(duration)) > 0 {
				return true
			}
			return false
		},
		"Schedule": func(in map[string]interface{}) string {
			pod := corev1.PodStatus{}
			marshal, _ := json.Marshal(in["status"])
			e := json.Unmarshal(marshal, &pod)
			if e != nil {
				r2, _ := json.Marshal(metav1.NewTime(time.Now()))
				return string(r2)
			}
			for _, c := range pod.Conditions {
				if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionTrue {
					r2, _ := json.Marshal(c.LastTransitionTime)
					return string(r2)
				}
			}

			return ""
		},
		"LastTime": func(in map[string]interface{}, key string, schedule string) string {
			pod := metav1.ObjectMeta{}
			marshal, _ := json.Marshal(in["metadata"])
			e := json.Unmarshal(marshal, &pod)
			if e != nil {
				return ""
			}
			start := metav1.Time{}
			e = json.Unmarshal([]byte(schedule), &start)
			if e != nil {
				return ""
			}
			success := pod.Annotations[key]
			duration, _ := time.ParseDuration(success)

			r2, _ := json.Marshal(metav1.NewTime(start.Add(duration)))
			return string(r2)
		},
	}
	for k, v := range conf.FuncMap {
		n.funcMap[k] = v
	}
	return n, nil
}

// Start starts the fake pod controller
// It will modify the pods status to we want
func (c *PodController) Start(ctx context.Context) error {
	go c.LockPods(ctx, c.lockPodChan)
	go c.DeletePods(ctx, c.deletePodChan)

	opt := metav1.ListOptions{
		FieldSelector: podFieldSelector,
	}
	err := c.WatchPods(ctx, c.lockPodChan, c.deletePodChan, opt)
	if err != nil {
		return fmt.Errorf("failed watch pods: %w", err)
	}
	go func() {
		err = c.ListPods(ctx, c.lockPodChan, opt)
		if err != nil {
			if c.logger != nil {
				c.logger.Printf("failed list pods: %s", err)
			}
		}
	}()
	return nil
}

// DeletePod deletes a pod
func (c *PodController) DeletePod(ctx context.Context, pod *corev1.Pod) error {
	if len(pod.Finalizers) != 0 {
		_, err := c.clientSet.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.MergePatchType, removeFinalizers, metav1.PatchOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return nil
			}
			return err
		}
	}

	err := c.clientSet.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, deleteOpt)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// DeletePods deletes pods from the channel
func (c *PodController) DeletePods(ctx context.Context, pods <-chan *corev1.Pod) {
	tasks := newParallelTasks(c.lockPodParallelism)
	for pod := range pods {
		localPod := pod
		tasks.Add(func() {
			err := c.DeletePod(ctx, localPod)
			if err != nil {
				if c.logger != nil {
					c.logger.Printf("Failed to delete pod %s.%s on %s: %s", localPod.Name, localPod.Namespace, localPod.Spec.NodeName, err)
				}
			} else {
				if c.logger != nil {
					//c.logger.Printf("Delete pod %s.%s on %s", pod.Name, pod.Namespace, pod.Spec.NodeName)
				}
			}
		})
	}
	tasks.Wait()
}

// LockPod locks a given pod
func (c *PodController) LockPod(ctx context.Context, pod *corev1.Pod) error {
	if c.podCustomStatusAnnotationSelector != nil &&
		len(pod.Annotations) != 0 &&
		c.podCustomStatusAnnotationSelector.Matches(labels.Set(pod.Annotations)) {
		return nil
	}
	provider := c.providers.Get(pod.Spec.NodeName)
	if pod.DeletionTimestamp != nil {
		provider.DeletePod(pod)
		c.DeletePod(ctx, pod)
		return nil
	}

	patch, err := c.configurePod(pod)
	if err != nil {
		c.logger.Printf("configurePod %s, err:%v", pod.Name, err)
		return err
	}

	defer func() {
		pod, err = c.clientSet.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err == nil && provider != nil {
			c.logger.Printf("Add Pod %s, Status:%s", pod.Name, pod.Status.Phase)
			provider.AddPod(pod)
		} else {
			c.logger.Printf("Add Pod %s, err:%v, provider:%v", pod.Name, err, provider)
		}
	}()

	if patch == nil {
		return nil
	}

	_, err = c.clientSet.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status")
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return nil
}

// LockPods locks a pods from the channel
func (c *PodController) LockPods(ctx context.Context, pods <-chan *corev1.Pod) {
	tasks := newParallelTasks(c.lockPodParallelism)
	for pod := range pods {
		localPod := pod
		tasks.Add(func() {
			err := c.LockPod(ctx, localPod)
			if err != nil {
				if c.logger != nil {
					c.logger.Printf("Failed to lock pod %s.%s on %s: %s", localPod.Name, localPod.Namespace, localPod.Spec.NodeName, err)
				}
			} else {
				if c.logger != nil {
					c.logger.Printf("Lock pod %s.%s on %s", localPod.Name, localPod.Namespace, localPod.Spec.NodeName)
				}
			}
		})
	}
	tasks.Wait()
}

// WatchPods watch pods put into the channel
func (c *PodController) WatchPods(ctx context.Context, lockChan, deleteChan chan<- *corev1.Pod, opt metav1.ListOptions) error {
	watcher, err := c.clientSet.CoreV1().Pods(corev1.NamespaceAll).Watch(ctx, opt)
	if err != nil {
		return err
	}

	go func() {
		rc := watcher.ResultChan()
	loop:
		for {
			select {
			case event, ok := <-rc:
				if !ok {
					for {
						watcher, err := c.clientSet.CoreV1().Pods(corev1.NamespaceAll).Watch(ctx, opt)
						if err == nil {
							rc = watcher.ResultChan()
							continue loop
						}

						if c.logger != nil {
							c.logger.Printf("Failed to watch pods: %s", err)
						}
						select {
						case <-ctx.Done():
							break loop
						case <-time.After(time.Second * 5):
						}
					}
				}
				switch event.Type {
				case watch.Added:
					pod := event.Object.(*corev1.Pod)
					if c.nodeHasFunc(pod.Spec.NodeName) {
						lockChan <- pod.DeepCopy()
						//} else {
						//	if c.logger != nil {
						//		c.logger.Printf("Skip pod %s.%s on %s: not take over", pod.Name, pod.Namespace, pod.Spec.NodeName)
						//	}
					}
				case watch.Modified:
					pod := event.Object.(*corev1.Pod)

					// At a Kubelet, we need to delete this pod on the node we take over
					if pod.DeletionTimestamp != nil {
						if c.nodeHasFunc(pod.Spec.NodeName) {
							deleteChan <- pod.DeepCopy()
						} else {
							if c.logger != nil {
								//c.logger.Printf("Skip pod %s.%s on %s: not take over", pod.Name, pod.Namespace, pod.Spec.NodeName)
							}
						}
					} else {
						if c.nodeHasFunc(pod.Spec.NodeName) {
							lockChan <- pod.DeepCopy()
						} else {
							if c.logger != nil {
								//c.logger.Printf("Skip pod %s.%s on %s: not take over", pod.Name, pod.Namespace, pod.Spec.NodeName)
							}
						}
					}
				case watch.Deleted:
					pod := event.Object.(*corev1.Pod)
					if c.nodeHasFunc(pod.Spec.NodeName) {
						// Recycling PodIP
						if pod.Status.PodIP != "" && c.cidrIPNet.Contains(net.ParseIP(pod.Status.PodIP)) {
							c.ipPool.Put(pod.Status.PodIP)
						}
					}
				}
			case <-ctx.Done():
				watcher.Stop()
				break loop
			}
		}
		if c.logger != nil {
			c.logger.Printf("Stop watch pods")
		}
	}()

	return nil
}

// ListPods list pods put into the channel
func (c *PodController) ListPods(ctx context.Context, ch chan<- *corev1.Pod, opt metav1.ListOptions) error {
	listPager := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return c.clientSet.CoreV1().Pods(corev1.NamespaceAll).List(ctx, opts)
	})

	return listPager.EachListItem(ctx, opt, func(obj runtime.Object) error {
		pod := obj.(*corev1.Pod)

		if c.nodeHasFunc(pod.Spec.NodeName) {
			ch <- pod.DeepCopy()
		}
		return nil
	})
}

// LockPodsOnNode locks pods on the node
func (c *PodController) LockPodsOnNode(ctx context.Context, nodeName string) error {
	return c.ListPods(ctx, c.lockPodChan, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	})
}

func (c *PodController) configurePod(pod *corev1.Pod) ([]byte, error) {

	// Mark the pod IP that existed before the kubelet was started
	if c.cidrIPNet.Contains(net.ParseIP(pod.Status.PodIP)) {
		c.ipPool.Use(pod.Status.PodIP)
	}

	temp := c.podStatusTemplate
	if m, ok := pod.Annotations[overwriteTemplateAnnotations]; ok && strings.TrimSpace(m) != "" {
		temp = m
	}

	patch, err := configurePod(pod, temp, c.funcMap)
	if err != nil {
		return nil, err
	}
	if patch == nil {
		return nil, nil
	}

	return json.Marshal(map[string]json.RawMessage{
		"status": patch,
	})
}

func configurePod(pod *corev1.Pod, temp string, funcMap template.FuncMap) ([]byte, error) {
	patch, err := toTemplateJson(temp, pod, funcMap)
	if err != nil {
		return nil, err
	}

	patch, err = modifyStatusByAnnotations(patch, pod.Annotations)
	if err != nil {
		return nil, err
	}

	// Check whether the pod need to be patch
	if pod.Status.Phase != corev1.PodPending {
		original, err := json.Marshal(pod.Status)
		if err != nil {
			return nil, err
		}

		sum, err := strategicpatch.StrategicMergePatch(original, patch, pod.Status)
		if err != nil {
			return nil, err
		}

		podStatus := corev1.PodStatus{}
		err = json.Unmarshal(sum, &podStatus)
		if err != nil {
			return nil, err
		}

		dist, err := json.Marshal(podStatus)
		if err != nil {
			return nil, err
		}

		if bytes.Equal(original, dist) {
			return nil, nil
		}
	}

	return patch, nil
}
