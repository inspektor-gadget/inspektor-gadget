package nvidia

import (
	"fmt"
	"sync"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	Name     = "nvidia"
	Priority = -999 // right after process operator
)

type nvidiaOperator struct {
}

func (s *nvidiaOperator) Name() string {
	return Name
}

func (s *nvidiaOperator) Priority() int {
	return Priority
}

func (s *nvidiaOperator) Init(params *params.Params) error {

	return nil
}

func (s *nvidiaOperator) GlobalParams() api.Params {
	return nil
}

func (s *nvidiaOperator) InstanceParams() api.Params {
	return nil
}

func (s *nvidiaOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	processDs, ok := gadgetCtx.GetDataSources()["processes"]
	if !ok {
		return nil, nil
	}

	pidAccessor := processDs.GetField("pid")
	if pidAccessor == nil {
		return nil, fmt.Errorf("pid field not found in process data source")
	}

	dsUtilAccessor, err := processDs.AddField("gpuusage", api.Kind_Uint32)
	if err != nil {
		return nil, fmt.Errorf("adding gpu_util field to process data source: %w",
			err)
	}

	dsMemAccessor, err := processDs.AddField("gpu_mem", api.Kind_Uint32)
	if err != nil {
		return nil, fmt.Errorf("adding gpu_mem field to process data source: %w",
			err)
	}

	if ret := nvml.Init(); ret != nvml.SUCCESS {
		// Don't give a hard error if the library is not found as many users
		// could have this not installed
		if ret == nvml.ERROR_LIBRARY_NOT_FOUND {
			// TODO: How to log this without annoying all users that don't care
			// about this library?
			gadgetCtx.Logger().Warnf("Unable to initialize NVML: %v", nvml.ErrorString(ret))
			return nil, nil
		}

		return nil, fmt.Errorf("initializing NVML: %v", nvml.ErrorString(ret))
	}

	return &nvidiaOperatorInstance{
		processDs:      processDs,
		pidAccessor:    pidAccessor,
		sdUtilAccessor: dsUtilAccessor,
		sdMemAccessor:  dsMemAccessor,
		done:           make(chan struct{}),
	}, nil
}

type nvidiaOperatorInstance struct {
	processDs   datasource.DataSource
	pidAccessor datasource.FieldAccessor

	sdUtilAccessor datasource.FieldAccessor
	sdMemAccessor  datasource.FieldAccessor

	deviceHandle nvml.Device
	existingPids map[uint32]struct{}
	done         chan struct{}
	mu           sync.Mutex
}

func (s *nvidiaOperatorInstance) Name() string {
	return Name
}

func (s *nvidiaOperatorInstance) Priority() int {
	return Priority
}

func (s *nvidiaOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	s.processDs.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
		pid, err := s.pidAccessor.Uint32(data)
		if err != nil {
			return fmt.Errorf("getting pid from process data source: %w", err)
		}

		if _, ok := s.existingPids[pid]; !ok {
			return nil
		}

		// TODO: Should I use GetProcessesUtilizationInfo instead?
		utils, ret := s.deviceHandle.GetProcessUtilization(uint64(pid))
		if ret != nvml.SUCCESS {
			return fmt.Errorf("unable to get utilization for process %d: %v", pid, nvml.ErrorString(ret))
		}

		// TODO: What if there are multiple instances of the same PID?
		for _, util := range utils {
			if util.Pid == pid {
				// TODO: do we need to sum enc and dec?
				s.sdUtilAccessor.PutUint32(data, util.SmUtil)
				s.sdMemAccessor.PutUint32(data, util.MemUtil)
				break
			}
		}

		return nil
	}, 0)

	return nil
}

func (s *nvidiaOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return fmt.Errorf("getting device count: %v", nvml.ErrorString(ret))
	}
	if count == 0 {
		return nil
	}

	// TODO: support multiple GPUs
	// questions
	// - The usage we report is relative only to a single GPU
	// - Memory reported is only in percentage, should we report bytes?
	// If a process is using multiple GPUs, how to report that?
	handle, ret := nvml.DeviceGetHandleByIndex(0)
	if ret != nvml.SUCCESS {
		return fmt.Errorf("getting device handle: %v", nvml.ErrorString(ret))
	}
	s.deviceHandle = handle

	go func() {
		// TODO: how oftern to do it?
		// TODO: probably needs to be shared among multiple gadgets
		timer := time.NewTicker(time.Second)

		for {
			select {
			case <-timer.C:
				s.mu.Lock()
				s.existingPids = make(map[uint32]struct{})
				processInfos, ret := s.deviceHandle.GetComputeRunningProcesses()
				if ret != nvml.SUCCESS {
					fmt.Printf("Unable to get process info: %v\n", nvml.ErrorString(ret))
					s.mu.Unlock()
					continue
				}

				for _, processInfo := range processInfos {
					s.existingPids[processInfo.Pid] = struct{}{}
				}
				s.mu.Unlock()

			case <-s.done:
				return
			}
		}
	}()

	return nil
}

func (s *nvidiaOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	close(s.done)

	return nil
}

func (s *nvidiaOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	if ret := nvml.Shutdown(); ret != nvml.SUCCESS {
		return fmt.Errorf("shutting down NVML: %v", nvml.ErrorString(ret))
	}

	return nil
}

func init() {
	operators.RegisterDataOperator(&nvidiaOperator{})
}
