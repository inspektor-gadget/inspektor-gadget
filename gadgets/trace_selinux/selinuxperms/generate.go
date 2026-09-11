// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package selinuxperms

//go:generate python3 generate_classperms.py --source testdata/classmap.h --output classperms.go
//go:generate python3 generate_classperms.py --source testdata/classmap.h --output classperms.go --check
