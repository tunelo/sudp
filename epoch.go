package sudp

import (
	"fmt"
)

type epochs struct {
	edkeys map[int]*dhss
	cEpoch int // Current Epoch
	nEpoch int // Next Epoch
}

func (e *epochs) init() {
	e.edkeys = make(map[int]*dhss)
	e.cEpoch = -1
	e.nEpoch = -1
}

func (e *epochs) new(epoch int) (*dhss, error) {
	var err error
	if e.nEpoch == -1 || epoch != e.nEpoch {
		if e.nEpoch != -1 && e.nEpoch != epoch {
			delete(e.edkeys, e.nEpoch)
		}
		e.nEpoch = epoch
		e.edkeys[e.nEpoch], err = newCipher()
	}
	return e.edkeys[e.nEpoch], err
}

func (e *epochs) current() (int, *dhss) {
	if e.cEpoch != -1 {
		return e.cEpoch, e.edkeys[e.cEpoch]
	}
	return -1, nil
}

func (e *epochs) pending() (int, *dhss) {
	if e.nEpoch != -1 {
		return e.nEpoch, e.edkeys[e.nEpoch]
	}
	return -1, nil
}
func (e *epochs) ecdh(remote []byte) error {
	if e.nEpoch != -1 {
		key := e.edkeys[e.nEpoch]
		return key.ecdh(remote)
	}
	return fmt.Errorf("key does not exist")
}

func (e *epochs) promote(n int) error {
	if e.nEpoch != -1 && e.nEpoch == n && e.edkeys[e.nEpoch].ready() {
		delete(e.edkeys, e.cEpoch)
		e.cEpoch = e.nEpoch
		e.nEpoch = -1
		return nil
	}
	return fmt.Errorf("impossible to promote next key")
}
