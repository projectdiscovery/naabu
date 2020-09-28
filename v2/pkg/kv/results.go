package kv

import "sync"

type D struct {
	sync.RWMutex
	M map[string]map[int]struct{}
}

func NewKVResults() *D {
	m := make(map[string]map[int]struct{})
	return &D{M: m}
}

func (kvd *D) AddPort(k string, v int) {
	kvd.Lock()
	defer kvd.Unlock()

	if _, ok := kvd.M[k]; !ok {
		kvd.M[k] = make(map[int]struct{})
	}

	kvd.M[k][v] = struct{}{}
}

func (kvd *D) SetPorts(k string, v map[int]struct{}) {
	kvd.Lock()
	defer kvd.Unlock()

	kvd.M[k] = v
}

func (kvd *D) Has(k string, v int) bool {
	kvd.RLock()
	defer kvd.RUnlock()

	vv, okk := kvd.M[k]
	if !okk {
		return false
	}
	_, okv := vv[v]

	return okv
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
