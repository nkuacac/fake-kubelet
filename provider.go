package fake_kubelet

import (
	"context"
	"fmt"
	cadvisorapi "github.com/google/cadvisor/info/v1"
	cadvisorv2 "github.com/google/cadvisor/info/v2"
	"github.com/wzshiming/fake-kubelet/informer"
	"github.com/wzshiming/fake-kubelet/metrics/collectors"
	"github.com/wzshiming/fake-kubelet/metrics/stats"
	statsapi "github.com/wzshiming/fake-kubelet/metrics/stats/v1alpha1"
	"io"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	compbasemetrics "k8s.io/component-base/metrics"
	"k8s.io/kubernetes/pkg/volume"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type FakeNode struct {
	Name     string
	Port     int
	Node     *v1.Node
	mut      sync.RWMutex
	Informer *informer.PodsInf
	started  bool
}

func (fn *FakeNode) Once() bool {
	fn.mut.Lock()
	defer fn.mut.Unlock()
	once := fn.started
	if !fn.started {
		fn.started = true
	}
	return once
}
func (fn *FakeNode) Start(logger Logger) {
	if !fn.Once() {
		s := time.Now()
		fn.Informer.Start()
		logger.Printf("informer start takes: %v", time.Since(s))
		go fn.Metrics(context.TODO(), logger)
	}
}

func (fn *FakeNode) Metrics(ctx context.Context, logger Logger) {
	resourceRegistry := compbasemetrics.NewKubeRegistry()
	resourceRegistry.CustomMustRegister(collectors.NewResourceMetricsCollector(stats.NewResourceAnalyzer(fn)))

	svc := &http.Server{
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
		Addr: fmt.Sprintf(":%d", fn.Port),
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

			switch r.URL.Path {
			case "/metrics/resource":
				handler := compbasemetrics.HandlerFor(resourceRegistry, compbasemetrics.HandlerOpts{ErrorHandling: compbasemetrics.ContinueOnError})
				handler.ServeHTTP(rw, r)
			default:
				logger.Printf("get url:%v %v\n", r.URL, r.RemoteAddr)
				http.NotFound(rw, r)
			}
		}),
	}

	csrname := "/pki/kubelet-tls.crt"
	keyname := "/pki/kubelet-tls.key"
	stat1, err1 := os.Stat(csrname)
	if err1 != nil {
		logger.Printf("/pki/kubelet-tls.crt %v", err1)
		return
	}
	stat2, err2 := os.Stat(keyname)
	if err2 != nil {
		logger.Printf("/pki/kubelet-tls.key %v", err2)
		return
	}
	logger.Printf("to start server %d, crt: %d, key: %d", fn.Port, stat1.Size(), stat2.Size())
	//dirname := "pki-" + fn.Name
	//if err := os.MkdirAll(dirname, 0644); err != nil {
	//	logger.Printf("prepare pkk dir failed", err)
	//	return
	//}
	//csrname := path.Join(dirname, "kubelet-tls.csr")
	//if err := File("/pki/kubelet-tls.csr", csrname); err != nil {
	//	logger.Printf("prepare kubelet-tls.csr", err)
	//	return
	//}
	//keyname := path.Join(dirname, "kubelet-tls.key")
	//if err := File("/pki/kubelet-tls.key", keyname); err != nil {
	//	logger.Printf("prepare kubelet-tls.crt", err)
	//	return
	//}

	err := svc.ListenAndServeTLS(csrname, keyname)
	if err != nil {
		logger.Printf("fatal start server %d, err:%v", fn.Port, err)
	}
	logger.Printf("success start server %d", fn.Port)
}
func File(src, dst string) error {
	var err error
	var srcfd *os.File
	var dstfd *os.File
	var srcinfo os.FileInfo

	if srcfd, err = os.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = os.Create(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = io.Copy(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}
	return os.Chmod(dst, srcinfo.Mode())
}
func NewFakeNode(name string, port int, c kubernetes.Interface) *FakeNode {
	return &FakeNode{
		Name:     name,
		Port:     port,
		Informer: informer.NewPodInformer(name, c),
		started:  false,
	}
}

func (fn *FakeNode) ListPodStats() ([]statsapi.PodStats, error) {
	return fn.ListPodCPUAndMemoryStats()
}

// ListPodCPUAndMemoryStats updates the cpu nano core usage for
// the containers and returns the stats for all the pod-managed containers.
func (fn *FakeNode) ListPodCPUAndMemoryStats() ([]statsapi.PodStats, error) {
	fn.mut.Lock()
	defer fn.mut.Unlock()
	var podStats []statsapi.PodStats
	for _, pod := range fn.Informer.List() {
		if pod.Status.Phase != v1.PodRunning {
			continue
		}
		var stats []statsapi.ContainerStats
		allc := uint64(0)
		allm := uint64(0)
		for _, container := range pod.Spec.Containers {
			cpu, mem := containerMetrics(pod, container)
			allc += cpu
			allm += mem
			stats = append(stats, statsapi.ContainerStats{
				StartTime: metav1.NewTime(time.Now()),
				Name:      container.Name,
				CPU: &statsapi.CPUStats{
					Time: metav1.NewTime(time.Now().Add(-1 * time.Second)),

					UsageCoreNanoSeconds: &cpu,
				},
				Memory: &statsapi.MemoryStats{
					Time:            metav1.NewTime(time.Now().Add(-1 * time.Second)),
					UsageBytes:      &mem,
					WorkingSetBytes: &mem,
				},
			})
		}
		podStats = append(podStats, statsapi.PodStats{
			PodRef: statsapi.PodReference{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				UID:       string(pod.UID),
			},
			StartTime:  metav1.NewTime(time.Now()),
			Containers: stats,
			CPU: &statsapi.CPUStats{
				Time:                 metav1.NewTime(time.Now().Add(-1 * time.Second)),
				UsageCoreNanoSeconds: &allc},
			Memory: &statsapi.MemoryStats{
				Time:       metav1.NewTime(time.Now().Add(-1 * time.Second)),
				UsageBytes: &allm, WorkingSetBytes: &allm},
		})
	}

	return podStats, nil
}

// ListPodStatsAndUpdateCPUNanoCoreUsage returns the stats of all the
// containers managed by pods and force update the cpu usageNanoCores.
// This is a workaround for CRI runtimes that do not integrate with
// cadvisor. See https://github.com/kubernetes/kubernetes/issues/72788
// for more details.
func (fn *FakeNode) ListPodStatsAndUpdateCPUNanoCoreUsage() ([]statsapi.PodStats, error) {
	return fn.ListPodCPUAndMemoryStats()
}

// ImageFsStats returns the stats of the image filesystem.
func (fn *FakeNode) ImageFsStats() (*statsapi.FsStats, error) {
	return nil, nil
}

// The following stats are provided by cAdvisor.

// GetCgroupStats returns the stats and the networking usage of the cgroup
// with the specified cgroupName.
func (fn *FakeNode) GetCgroupStats(cgroupName string, updateStats bool) (*statsapi.ContainerStats, *statsapi.NetworkStats, error) {
	return nil, nil, nil
}

// GetCgroupCPUAndMemoryStats returns the CPU and memory stats of the cgroup with the specified cgroupName.
func (fn *FakeNode) GetCgroupCPUAndMemoryStats(cgroupName string, updateStats bool) (*statsapi.ContainerStats, error) {
	fn.mut.Lock()
	defer fn.mut.Unlock()
	var stats statsapi.ContainerStats

	allc := uint64(0)
	allm := uint64(0)
	for _, pod := range fn.Informer.List() {
		if pod.Status.Phase != v1.PodRunning {
			continue
		}
		for _, container := range pod.Spec.Containers {
			cpu, mem := containerMetrics(pod, container)
			allc += cpu
			allm += mem
		}
	}
	stats = statsapi.ContainerStats{
		Name:      cgroupName,
		StartTime: metav1.NewTime(time.Now()),
		CPU: &statsapi.CPUStats{
			Time:                 metav1.NewTime(time.Now().Add(-1 * time.Second)),
			UsageCoreNanoSeconds: &allc,
		},
		Memory: &statsapi.MemoryStats{
			Time:            metav1.NewTime(time.Now().Add(-1 * time.Second)),
			UsageBytes:      &allm,
			WorkingSetBytes: &allm,
		},
	}
	return &stats, nil
}

func cpuFromAnnotations(pod *v1.Pod, cpu *uint64) bool {
	if pod.Annotations != nil {
		if c, ok := pod.Annotations["use-cpu-default"]; ok {
			*cpu = uint64(c2i(c)) * uint64(time.Since(pod.Status.StartTime.Time).Microseconds())
			return true
		}
	}
	return false
}

func cpuFromLimit(pod *v1.Pod, container v1.Container, cpu *uint64) bool {
	if container.Resources.Limits != nil {
		if container.Resources.Limits.Cpu().MilliValue() > 0 {
			*cpu = uint64(container.Resources.Limits.Cpu().MilliValue()) * uint64(time.Since(pod.Status.StartTime.Time).Microseconds())
			return true
		}
	}
	return false
}

func cpuFromRequest(pod *v1.Pod, container v1.Container, cpu *uint64) bool {
	if container.Resources.Requests != nil {
		if container.Resources.Requests.Cpu().MilliValue() > 0 {
			*cpu = uint64(container.Resources.Requests.Cpu().MilliValue()) * uint64(time.Since(pod.Status.StartTime.Time).Microseconds()) * 3 / 100
			return true
		}
	}
	return false
}

func memFromAnnotations(pod *v1.Pod, mem *uint64) bool {
	if pod.Annotations != nil {
		if m, ok := pod.Annotations["use-mem-default"]; ok {
			*mem = uint64(m2i(m))
			return true
		}
	}
	return false
}

func memFromLimit(container v1.Container, mem *uint64) bool {
	if container.Resources.Limits != nil {
		if container.Resources.Limits.Memory().Value() > 0 {
			*mem = uint64(container.Resources.Limits.Memory().Value())
			return true
		}
	}
	return false
}

func memFromRequest(container v1.Container, mem *uint64) bool {
	if container.Resources.Requests != nil {
		if container.Resources.Requests.Memory().Value() > 0 {
			*mem = uint64(container.Resources.Requests.Memory().Value()) * 50 / 100
			return true
		}
	}
	return false
}

func containerMetrics(pod *v1.Pod, container v1.Container) (uint64, uint64) {
	cpu := uint64(c2i("200m")) * uint64(time.Since(pod.Status.StartTime.Time).Microseconds())
	mem := uint64(m2i("200Mi"))
	if cpuFromAnnotations(pod, &cpu) || cpuFromLimit(pod, container, &cpu) || cpuFromRequest(pod, container, &cpu) {
	}
	if memFromAnnotations(pod, &mem) || memFromLimit(container, &mem) || memFromRequest(container, &mem) {
	}

	return cpu, mem
}

func c2i(in string) int64 {
	v := resource.MustParse(in)
	return v.MilliValue()
}
func m2i(in string) int64 {
	v := resource.MustParse(in)
	return v.Value()
}

// RootFsStats returns the stats of the node root filesystem.
func (fn *FakeNode) RootFsStats() (*statsapi.FsStats, error) {
	return nil, nil
}

// The following stats are provided by cAdvisor for legacy usage.

// GetContainerInfo returns the information of the container with the
// containerName managed by the pod with the uid.
func (fn *FakeNode) GetContainerInfo(podFullName string, uid types.UID, containerName string, req *cadvisorapi.ContainerInfoRequest) (*cadvisorapi.ContainerInfo, error) {
	return nil, nil
}

// GetRawContainerInfo returns the information of the container with the
// containerName. If subcontainers is true, this function will return the
// information of all the sub-containers as well.
func (fn *FakeNode) GetRawContainerInfo(containerName string, req *cadvisorapi.ContainerInfoRequest, subcontainers bool) (map[string]*cadvisorapi.ContainerInfo, error) {
	return nil, nil
}

// GetRequestedContainersInfo returns the information of the container with
// the containerName, and with the specified cAdvisor options.
func (fn *FakeNode) GetRequestedContainersInfo(containerName string, options cadvisorv2.RequestOptions) (map[string]*cadvisorapi.ContainerInfo, error) {
	return nil, nil
}

// The following information is provided by Kubelet.

// GetPodByName returns the spec of the pod with the name in the specified
// namespace.
func (fn *FakeNode) GetPodByName(namespace, name string) (*v1.Pod, bool) {
	return nil, true
}

// GetNode returns the spec of the local node.
func (fn *FakeNode) GetNode() (*v1.Node, error) {
	return fn.Node, nil
}

// GetNodeConfig returns the configuration of the local node.
func (fn *FakeNode) GetNodeConfig() stats.NodeConfig {
	return stats.NodeConfig{
		RuntimeCgroupsName:                       "RuntimeCgroupsName",
		SystemCgroupsName:                        "SystemCgroupsName",
		KubeletCgroupsName:                       "KubeletCgroupsName",
		KubeletOOMScoreAdj:                       0,
		ContainerRuntime:                         "ContainerRuntime",
		CgroupsPerQOS:                            false,
		CgroupRoot:                               "CgroupRoot",
		CgroupDriver:                             "CgroupDriver",
		KubeletRootDir:                           "KubeletRootDir",
		ProtectKernelDefaults:                    false,
		QOSReserved:                              nil,
		CPUManagerPolicy:                         "CPUManagerPolicy",
		CPUManagerPolicyOptions:                  nil,
		ExperimentalTopologyManagerScope:         "ExperimentalTopologyManagerScope",
		CPUManagerReconcilePeriod:                0,
		ExperimentalMemoryManagerPolicy:          "ExperimentalMemoryManagerPolicy",
		ExperimentalPodPidsLimit:                 0,
		EnforceCPULimits:                         false,
		CPUCFSQuotaPeriod:                        0,
		ExperimentalTopologyManagerPolicy:        "ExperimentalTopologyManagerPolicy",
		ExperimentalTopologyManagerPolicyOptions: nil,
	}
}

// ListVolumesForPod returns the stats of the volume used by the pod with
// the podUID.
func (fn *FakeNode) ListVolumesForPod(podUID types.UID) (map[string]volume.Volume, bool) {
	return nil, false
}

// ListBlockVolumesForPod returns the stats of the volume used by the
// pod with the podUID.
func (fn *FakeNode) ListBlockVolumesForPod(podUID types.UID) (map[string]volume.BlockVolume, bool) {
	return nil, false
}

// GetPods returns the specs of all the pods running on this node.
func (fn *FakeNode) GetPods() []*v1.Pod {
	var pods []*v1.Pod
	for _, pod := range fn.Informer.List() {
		pods = append(pods, pod)
	}
	return pods
}

// RlimitStats returns the rlimit stats of system.
func (fn *FakeNode) RlimitStats() (*statsapi.RlimitStats, error) {
	return nil, nil
}

// GetPodCgroupRoot returns the literal cgroupfs value for the cgroup containing all pods
func (fn *FakeNode) GetPodCgroupRoot() string {
	return "GetPodCgroupRoot"
}

// GetPodByCgroupfs provides the pod that maps to the specified cgroup literal, as well
// as whether the pod was found.
func (fn *FakeNode) GetPodByCgroupfs(cgroupfs string) (*v1.Pod, bool) {
	return nil, true
}

type providerSets struct {
	mut  sync.RWMutex
	sets map[string]*FakeNode
}

func newProviderSets() *providerSets {
	return &providerSets{
		sets: make(map[string]*FakeNode),
	}
}

func (s *providerSets) Size() int {
	s.mut.RLock()
	defer s.mut.RUnlock()
	return len(s.sets)
}

func (s *providerSets) Put(key string, provider *FakeNode) {
	s.mut.Lock()
	defer s.mut.Unlock()
	s.sets[key] = provider
}

func (s *providerSets) Delete(key string) {
	s.mut.Lock()
	defer s.mut.Unlock()
	delete(s.sets, key)
}

func (s *providerSets) Get(key string) *FakeNode {
	s.mut.Lock()
	defer s.mut.Unlock()
	return s.sets[key]
}

func (s *providerSets) Has(key string) bool {
	s.mut.RLock()
	defer s.mut.RUnlock()
	_, ok := s.sets[key]
	return ok
}

func (s *providerSets) Foreach(f func(string)) {
	s.mut.RLock()
	defer s.mut.RUnlock()
	for k := range s.sets {
		f(k)
	}
}
