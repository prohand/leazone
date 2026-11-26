package dhcpconf

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Option is a custom DHCP option.
type Option struct {
	Code  int    `json:"code"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Codes managed by dedicated fields or by the protocol itself.
var reservedCodes = map[int]string{
	1: "masque (champ réseau)", 3: "passerelle", 6: "serveurs DNS", 15: "domaine", 42: "serveurs NTP",
	51: "durée du bail", 50: "protocole", 53: "protocole", 54: "protocole", 55: "protocole",
	58: "protocole", 59: "protocole", 61: "protocole", 82: "protocole (relais)",
}

// Encode validates an option and returns its wire value.
func (o Option) Encode() ([]byte, error) {
	if o.Code < 1 || o.Code > 254 {
		return nil, fmt.Errorf("code entre 1 et 254")
	}
	if why, ok := reservedCodes[o.Code]; ok {
		return nil, fmt.Errorf("l'option %d est gérée par Leazone (%s)", o.Code, why)
	}
	v := strings.TrimSpace(o.Value)
	switch o.Type {
	case "ip":
		a, err := parseV4(v)
		if err != nil {
			return nil, err
		}
		b := a.As4()
		return b[:], nil
	case "ips":
		var out []byte
		for _, part := range strings.Split(v, ",") {
			a, err := parseV4(part)
			if err != nil {
				return nil, err
			}
			b := a.As4()
			out = append(out, b[:]...)
		}
		return out, nil
	case "string":
		if v == "" || len(v) > 255 {
			return nil, fmt.Errorf("texte de 1 à 255 caractères")
		}
		return []byte(v), nil
	case "u8", "u16", "u32":
		bits := map[string]int{"u8": 8, "u16": 16, "u32": 32}[o.Type]
		n, err := strconv.ParseUint(v, 10, bits)
		if err != nil {
			return nil, fmt.Errorf("nombre entier attendu (%d bits)", bits)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(n))
		return b[4-bits/8:], nil
	case "bool":
		switch strings.ToLower(v) {
		case "true", "1", "oui":
			return []byte{1}, nil
		case "false", "0", "non":
			return []byte{0}, nil
		}
		return nil, fmt.Errorf("true ou false attendu")
	case "hex":
		_, b, err := NormalizeHex(v)
		if err != nil || len(b) == 0 || len(b) > 255 {
			return nil, fmt.Errorf("octets hexadécimaux attendus (ex : 01:02:0a)")
		}
		return b, nil
	}
	return nil, fmt.Errorf("type inconnu (ip, ips, string, u8, u16, u32, bool, hex)")
}
