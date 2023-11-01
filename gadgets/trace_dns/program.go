package main

import (
	"fmt"

	wapc "github.com/wapc/wapc-guest-tinygo"
)

func main() {
	wapc.RegisterFunctions(wapc.Functions{
		"Init":         Init,
		"column_name":  column_name,
		"column_qr":    column_qr,
		"column_qtype": column_qtype,
		"column_rcode": column_rcode,
	})
}

func Init(payload []byte) ([]byte, error) {
	return nil, nil
}

// List taken from:
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
var qTypeNames = map[int]string{
	1:     "A",
	2:     "NS",
	3:     "MD",
	4:     "MF",
	5:     "CNAME",
	6:     "SOA",
	7:     "MB",
	8:     "MG",
	9:     "MR",
	10:    "NULL",
	11:    "WKS",
	12:    "PTR",
	13:    "HINFO",
	14:    "MINFO",
	15:    "MX",
	16:    "TXT",
	17:    "RP",
	18:    "AFSDB",
	19:    "X25",
	20:    "ISDN",
	21:    "RT",
	22:    "NSAP",
	23:    "NSAP-PTR",
	24:    "SIG",
	25:    "KEY",
	26:    "PX",
	27:    "GPOS",
	28:    "AAAA",
	29:    "LOC",
	30:    "NXT",
	31:    "EID",
	32:    "NIMLOC",
	33:    "SRV",
	34:    "ATMA",
	35:    "NAPTR",
	36:    "KX",
	37:    "CERT",
	38:    "A6",
	39:    "DNAME",
	40:    "SINK",
	41:    "OPT",
	42:    "APL",
	43:    "DS",
	44:    "SSHFP",
	45:    "IPSECKEY",
	46:    "RRSIG",
	47:    "NSEC",
	48:    "DNSKEY",
	49:    "DHCID",
	50:    "NSEC3",
	51:    "NSEC3PARAM",
	52:    "TLSA",
	53:    "SMIMEA",
	55:    "HIP",
	56:    "NINFO",
	57:    "RKEY",
	58:    "TALINK",
	59:    "CDS",
	60:    "CDNSKEY",
	61:    "OPENPGPKEY",
	62:    "CSYNC",
	63:    "ZONEMD",
	64:    "SVCB",
	65:    "HTTPS",
	99:    "SPF",
	100:   "UINFO",
	101:   "UID",
	102:   "GID",
	103:   "UNSPEC",
	104:   "NID",
	105:   "L32",
	106:   "L64",
	107:   "LP",
	108:   "EUI48",
	109:   "EUI64",
	249:   "TKEY",
	250:   "TSIG",
	251:   "IXFR",
	252:   "AXFR",
	253:   "MAILB",
	254:   "MAILA",
	255:   "*",
	256:   "URI",
	257:   "CAA",
	258:   "AVC",
	259:   "DOA",
	260:   "AMTRELAY",
	32768: "TA",
	32769: "DLV",
}

// DNS header RCODE (response code) field.
// https://datatracker.ietf.org/doc/rfc1035#section-4.1.1
var rCodeNames = map[int]string{
	0: "NoError",
	1: "FormErr",
	2: "ServFail",
	3: "NXDomain",
	4: "NotImp",
	5: "Refused",
}

func column_name(payload []byte) ([]byte, error) {
	var str string
	for i := 0; i < len(payload); i++ {
		length := int(payload[i])
		if length == 0 {
			break
		}
		if i+1+length < len(payload) {
			str += string(payload[i+1:i+1+length]) + "."
		} else {
			wapc.ConsoleLog(fmt.Sprintf("invalid payload %+v\n", payload))
		}
		i += length
	}
	return []byte(str), nil
}

func column_qr(payload []byte) ([]byte, error) {
	if len(payload) != 1 {
		return nil, fmt.Errorf("invalid payload %+v\n", payload)
	}
	switch payload[0] {
	case 0:
		return []byte("Q"), nil
	case 1:
		return []byte("R"), nil
	}
	return nil, fmt.Errorf("invalid payload %+v\n", payload)
}

func column_qtype(payload []byte) ([]byte, error) {
	if len(payload) != 1 {
		return nil, fmt.Errorf("invalid payload %+v\n", payload)
	}
	qType, ok := qTypeNames[int(payload[0])]
	if !ok {
		return []byte("UNASSIGNED"), nil
	}
	return []byte(qType), nil
}

func column_rcode(payload []byte) ([]byte, error) {
	if len(payload) != 1 {
		return nil, fmt.Errorf("invalid payload %+v\n", payload)
	}
	rcode, ok := rCodeNames[int(payload[0])]
	if !ok {
		return []byte(""), nil
	}
	return []byte(rcode), nil
}
