package fake_kubelet

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"text/template"
	"time"

	"sigs.k8s.io/yaml"
)

func parseCIDR(s string) (*net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	ipnet.IP = ip
	return ipnet, nil
}

func addIp(ip net.IP, add uint64) net.IP {
	if len(ip) < 8 {
		return ip
	}

	out := make(net.IP, len(ip))
	copy(out, ip)

	i := binary.BigEndian.Uint64(out[len(out)-8:])
	i += add

	binary.BigEndian.PutUint64(out[len(out)-8:], i)
	return out
}

type ipPool struct {
	mut    sync.Mutex
	used   map[string]struct{}
	usable map[string]struct{}
	cidr   *net.IPNet
	index  uint64
}

func newIPPool(cidr *net.IPNet) *ipPool {
	return &ipPool{
		used:   make(map[string]struct{}),
		usable: make(map[string]struct{}),
		cidr:   cidr,
	}
}

func (i *ipPool) new() string {
	for {
		ip := addIp(i.cidr.IP, i.index).String()
		i.index++

		if _, ok := i.used[ip]; ok {
			continue
		}

		i.used[ip] = struct{}{}
		i.usable[ip] = struct{}{}
		return ip
	}
}

func (i *ipPool) Get() string {
	i.mut.Lock()
	defer i.mut.Unlock()
	ip := ""
	if len(i.usable) != 0 {
		for s := range i.usable {
			ip = s
		}
	}
	if ip == "" {
		ip = i.new()
	}
	delete(i.usable, ip)
	i.used[ip] = struct{}{}
	return ip
}

func (i *ipPool) Put(ip string) {
	i.mut.Lock()
	defer i.mut.Unlock()
	if !i.cidr.Contains(net.ParseIP(ip)) {
		return
	}
	delete(i.used, ip)
	i.usable[ip] = struct{}{}
}

func (i *ipPool) Use(ip string) {
	i.mut.Lock()
	defer i.mut.Unlock()
	if !i.cidr.Contains(net.ParseIP(ip)) {
		return
	}
	i.used[ip] = struct{}{}
}

func toTemplateJson(text string, original interface{}, funcMap template.FuncMap) ([]byte, error) {
	text = strings.TrimSpace(text)
	v, ok := templateCache.Load(text)
	if !ok {
		temp, err := template.New("_").Funcs(funcMap).Parse(text)
		if err != nil {
			return nil, err
		}
		templateCache.Store(text, temp)
		v = temp
	}
	temp := v.(*template.Template)
	buf := bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(buf)

	buf.Reset()
	err := json.NewEncoder(buf).Encode(original)
	if err != nil {
		return nil, err
	}

	var data interface{}
	decoder := json.NewDecoder(buf)
	decoder.UseNumber()
	err = decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	buf.Reset()
	err = temp.Execute(buf, data)
	if err != nil {
		return nil, err
	}

	out, err := yaml.YAMLToJSON(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, buf.String())
	}
	return out, nil
}

var (
	templateCache = sync.Map{}
	bufferPool    = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}
)

type parallelTasks struct {
	wg     sync.WaitGroup
	bucket chan struct{}
	tasks  chan func()
}

func newParallelTasks(n int) *parallelTasks {
	return &parallelTasks{
		bucket: make(chan struct{}, n),
		tasks:  make(chan func()),
	}
}

func (p *parallelTasks) Add(fun func()) {
	p.wg.Add(1)
	select {
	case p.tasks <- fun: // there are idle threads
	case p.bucket <- struct{}{}: // there are free threads
		go p.fork()
		p.tasks <- fun
	default: // no idle threads and no free threads
		p.tasks <- fun
	}
}

func (p *parallelTasks) fork() {
	defer func() {
		<-p.bucket
	}()
	timer := time.NewTimer(time.Second / 2)
	for {
		select {
		case <-timer.C: // idle threads
			return
		case fun := <-p.tasks:
			timer.Reset(time.Second / 2)
			fun()
			p.wg.Done()
		}
	}
}

func (p *parallelTasks) Wait() {
	p.wg.Wait()
}

type stringSets struct {
	mut  sync.RWMutex
	sets map[string]struct{}
}

func newStringSets() *stringSets {
	return &stringSets{
		sets: make(map[string]struct{}),
	}
}

func (s *stringSets) Put(key string) {
	s.mut.Lock()
	defer s.mut.Unlock()
	s.sets[key] = struct{}{}
}

func (s *stringSets) Delete(key string) {
	s.mut.Lock()
	defer s.mut.Unlock()
	delete(s.sets, key)
}

func (s *stringSets) Has(key string) bool {
	s.mut.RLock()
	defer s.mut.RUnlock()
	_, ok := s.sets[key]
	return ok
}

func (s *stringSets) Foreach(f func(string)) {
	s.mut.RLock()
	defer s.mut.RUnlock()
	for k := range s.sets {
		f(k)
	}
}
