package store

import (
	"errors"
	"sync"
)

// resolve ip to mac address

var (
	Global *Store

	ErrARPNotFound = errors.New("not exist in arp table")
)

func init() {
	Global = NewStore()
}

type Store struct {
	mu sync.Mutex

	ARP map[string]string
}

func (s *Store) SetARP(ip, mac []byte) {
	s.ARP[string(ip)] = string(mac)
}

func (s *Store) GetARP(ip []byte) ([]byte, error) {
	v, ok := s.ARP[string(ip)]
	if !ok {
		return []byte{}, ErrARPNotFound
	}
	return []byte(v), nil
}

func NewStore() *Store {
	arp := make(map[string]string, 0)
	store := &Store{ARP: arp}

	return store
}
