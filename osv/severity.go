package osv

type Severity string

const (
	Unknown  = Severity("")
	Low      = Severity("LOW")
	Medium   = Severity("MEDIUM")
	High     = Severity("HIGH")
	Critical = Severity("CRITICAL")
)

var SeverityMap = map[Severity]int{
	Unknown:  -1,
	Low:      0,
	Medium:   1,
	High:     2,
	Critical: 3,
}
