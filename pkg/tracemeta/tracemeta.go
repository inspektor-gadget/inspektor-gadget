package tracemeta

type TraceMeta struct {
	Status       string `json:"status,omitempty"`
	TraceID      string `json:"traceid,omitempty"`
	ContainerID  string `json:"containerid,omitempty"`
	UID          string `json:"uid,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Podname      string `json:"podname,omitempty"`
	Containeridx int    `json:"containeridx,omitempty"`
	TimeCreation string `json:"timecreation,omitempty"`
	TimeDeletion string `json:"timedeletion,omitempty"`
	Capabilities uint64 `json:"capabilities,omitempty"`
}
