package sudp

import (
	"fmt"
	"time"
)

const (
	offsetTolerance = 10 * time.Second
	maxMessageDelay = 5 * time.Second
)

type timeSync struct {
	offset time.Duration
}

func newTimeSync(remoteTime uint64) (*timeSync, error) {
	peer := time.UnixMilli(int64(remoteTime))
	offset := time.Now().Sub(peer)

	if offset.Abs() > offsetTolerance {
		return nil, fmt.Errorf("offset between hosts too large")
	}
	return &timeSync{
		offset: offset,
	}, nil
}

func (ts *timeSync) inTime(msgTimestamp uint64) bool {
	sent := time.UnixMilli(int64(msgTimestamp)).Add(ts.offset)
	host := time.Now()
	if sent.Before(host.Add(-maxMessageDelay)) { //|| sent.After(host) {
		return false
	}
	return true
}
