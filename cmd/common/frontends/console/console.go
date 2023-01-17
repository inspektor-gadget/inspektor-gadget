// Copyright 2022-2023 The Inspektor Gadget authors
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

package console

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/term"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

type frontend struct {
	ctx    context.Context
	cancel func()
}

func NewFrontend() frontends.Frontend {
	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Debugf("got signal, cancelling context")
		cancel()
		<-stop
		log.Debugf("got signal again, exiting")
		// On second signal, exit forcefully
		os.Exit(1)
	}()
	return &frontend{
		ctx:    ctx,
		cancel: cancel,
	}
}

func (f *frontend) Clear() {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		commonutils.ClearScreen()
	}
}

func (f *frontend) Output(payload string) {
	fmt.Fprintln(os.Stdout, payload)
}

func (f *frontend) Error(severity logger.Level, message string) {
	fmt.Fprintln(os.Stderr, message)
}

func (f *frontend) GetContext() context.Context {
	return f.ctx
}

func (f *frontend) Close() {
	f.cancel()
	f.ctx = nil
}
