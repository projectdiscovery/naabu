package KV

import "sync"

type KVD struct {
	sync.RWMutex
	M map[string]map[int]struct{}
}

func NewKVResults() *KVD {
	m := make(map[string]map[int]struct{})
	return &KVD{M: m}
}

func (kvd *KVD) AddPort(k string, v int) {
	kvd.Lock()
	defer kvd.Unlock()

	if _, ok := kvd.M[k]; !ok {
		kvd.M[k] = make(map[int]struct{})
	}

	kvd.M[k][v] = struct{}{}
}

func (kvd *KVD) SetPorts(k string, v map[int]struct{}) {
	kvd.Lock()
	defer kvd.Unlock()

	kvd.M[k] = v
}

func (kvd *KVD) Has(k string, v int) bool {
	kvd.RLock()
	defer kvd.RUnlock()

	vv, okk := kvd.M[k]
	if !okk {
		return false
	}
	_, okv := vv[v]
	if okv {
		return true
	}

	return false
}

type KV struct {
	sync.RWMutex
	M map[string]struct{}
}

func NewKV() *KV {
	m := make(map[string]struct{})
	return &KV{M: m}
}

func (kv *KV) Set(k string) {
	kv.Lock()
	defer kv.Unlock()

	kv.M[k] = struct{}{}
}

func (kv *KV) Has(k string) bool {
	kv.RLock()
	defer kv.RUnlock()

	_, ok := kv.M[k]
	return ok
}

func sliceIntContains(s []int, v int) bool {
	for _, p := range s {
		if p == v {
			return true
		}
	}

	return false
}
