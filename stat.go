package sudp

import "sync"

const (
	statOpen  = true
	statClose = false
)

type stat struct {
	flag bool
	lock sync.RWMutex
}

func (s *stat) isOpen() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.flag == statOpen
}

func (s *stat) setStat(f bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.flag = f
}
