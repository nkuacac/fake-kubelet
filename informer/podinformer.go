package informer

import (
	corev1 "k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"time"
)

type PodsInf struct {
	StopCh   chan struct{}
	stop     bool
	informer v1.PodInformer
	start    time.Time
	nodeName string
}

func NewPodInformer(nodeName string, c kubernetes.Interface) *PodsInf {
	tweakListOptions := func(options *v12.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
	}

	ef := informers.NewSharedInformerFactoryWithOptions(c, 0, informers.WithTweakListOptions(tweakListOptions))
	informer := ef.Core().V1().Pods()

	return &PodsInf{
		StopCh:   make(chan struct{}),
		nodeName: nodeName,
		stop:     false,
		informer: informer,
	}
}
func (efr *PodsInf) Stop() time.Duration {
	close(efr.StopCh)
	efr.stop = true
	return time.Since(efr.start)
}

func (efr *PodsInf) Start() {
	go efr.informer.Informer().Run(efr.StopCh)
	cache.WaitForCacheSync(efr.StopCh, efr.informer.Informer().HasSynced)
}

func (efr *PodsInf) List() []*corev1.Pod {
	pods, err := efr.informer.Lister().List(labels.NewSelector())
	if err != nil {
		return nil
	}
	return pods
}
