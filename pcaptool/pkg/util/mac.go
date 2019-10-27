package util

import "github.com/umahmood/macvendors"

type MacAddress interface {
	Address() string
	Company() string
	Country() string
	Type() string
	MacPrefix() string
}

type MacAddr struct {
	address   string
	company   string
	country   string
	macPrefix string
}

func (m *MacAddr) Address() string {
	return m.address
}

func (m *MacAddr) Company() string {
	return m.company
}

func (m *MacAddr) Country() string {
	return m.country
}

func (m *MacAddr) MacPrefix() string {
	return m.macPrefix
}

func LookupMacAddress(mac string) (*MacAddr, error) {
	vendor := macvendors.New()
	m, err := vendor.Lookup(mac)
	if err != nil {
		return nil, err
	}
	macAddr := &MacAddr{
		address:   m.Address,
		company:   m.Company,
		country:   m.Country,
		macPrefix: m.MacPrefix,
	}
	return macAddr, err
}
