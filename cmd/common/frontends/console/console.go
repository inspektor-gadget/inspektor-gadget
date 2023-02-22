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
	ctx        context.Context
	cancel     func()
	log        logger.Logger
	isTerminal bool
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
		ctx:        ctx,
		cancel:     cancel,
		isTerminal: term.IsTerminal(int(os.Stdout.Fd())),
		log:        logger.DefaultLogger(),
	}
}

func (f *frontend) Logf(severity logger.Level, fmt string, params ...any) {
	switch severity {
	case logger.PanicLevel:
		f.log.Panicf(fmt, params)
	case logger.FatalLevel:
		f.log.Fatalf(fmt, params)
	case logger.ErrorLevel:
		f.log.Errorf(fmt, params)
	case logger.WarnLevel:
		f.log.Warnf(fmt, params)
	case logger.InfoLevel:
		f.log.Infof(fmt, params)
	case logger.DebugLevel:
		f.log.Debugf(fmt, params)
	case logger.TraceLevel:
		f.log.Tracef(fmt, params)
	}
}

func (f *frontend) Clear() {
	if f.isTerminal {
		commonutils.ClearScreen()
	}
}

func (f *frontend) Output(payload string) {
	fmt.Fprintln(os.Stdout, payload)
}

func (f *frontend) GetContext() context.Context {
	return f.ctx
}

func (f *frontend) Close() {
	f.cancel()
	f.ctx = nil
}
