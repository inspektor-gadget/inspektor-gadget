// Copyright 2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpcruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func getCatalogFilename() (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	configFile := filepath.Join(homedir, ".ig", "catalog.json")
	return configFile, nil
}

func loadLocalGadgetCatalog() (*runtime.Catalog, error) {
	catalogFile, err := getCatalogFilename()
	if err != nil {
		return nil, fmt.Errorf("get catalog filename: %w", err)
	}

	f, err := os.Open(catalogFile)
	if err != nil {
		return nil, fmt.Errorf("open catalog file: %w", err)
	}

	catalog := &runtime.Catalog{}

	dec := json.NewDecoder(f)
	err = dec.Decode(&catalog)
	if err != nil {
		return nil, fmt.Errorf("reading catalog: %w", err)
	}

	return catalog, err
}

func loadRemoteGadgetCatalog() (*runtime.Catalog, error) {
	ctx, cancelDial := context.WithTimeout(context.Background(), time.Second*ConnectTimeout)
	defer cancelDial()

	// Get a random gadget pod and get the catalog from there
	pods, err := getGadgetPods(ctx, []string{})
	if err != nil {
		return nil, fmt.Errorf("get gadget pods: %w", err)
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("no valid pods found to get catalog from")
	}

	pod := pods[0]
	dialOpt := grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
		return NewK8SExecConn(ctx, pod, time.Second*ConnectTimeout)
		// return NewK8SPortForwardConn(ctx, s, time.Second*30)
	})

	conn, err := grpc.DialContext(ctx, "", dialOpt, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("dialing gadget pod on node %q: %w", pod.node, err)
	}
	client := pb.NewGadgetManagerClient(conn)
	defer conn.Close()

	info, err := client.GetInfo(ctx, &pb.InfoRequest{Version: "1.0"})
	if err != nil {
		return nil, fmt.Errorf("get info from gadget pod: %w", err)
	}

	catalog := &runtime.Catalog{}
	err = json.Unmarshal(info.Catalog, &catalog)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling catalog: %w", err)
	}

	return catalog, nil
}

func storeCatalog(catalog *runtime.Catalog) error {
	catalogFile, err := getCatalogFilename()
	if err != nil {
		return fmt.Errorf("get catalog filename: %w", err)
	}
	err = os.MkdirAll(filepath.Dir(catalogFile), 0o750)
	if err != nil && errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create config dir: %w", err)
	}
	catalogJSON, err := json.Marshal(catalog)
	if err != nil {
		return fmt.Errorf("marshaling catalog JSON: %w", err)
	}
	err = os.WriteFile(catalogFile, catalogJSON, 0o644)
	if err != nil {
		return fmt.Errorf("write catalog file: %w", err)
	}
	return nil
}
