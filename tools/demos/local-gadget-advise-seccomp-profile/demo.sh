#!/bin/bash
# Copyright 2016 The Kubernetes Authors.
# Copyright 2022 The Inspektor Gadget authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
source $(dirname ${BASH_SOURCE})/../util.sh

desc "Let's create a nginx container with a seccomp profile installed!"
profile_json=$(relative profile.json)
run "docker run --rm --name nginx-container -p 8081:80 -d --security-opt seccomp=${profile_json} nginx"

desc "Let's query it!"
run "curl localhost:8081"

desc "Hum... Something wrong occurred! Maybe our seccomp profile is wrong? Let's use local-gadget to help us!"
sleep 5

tmux new -d -s demo-session \
	"$(dirname ${BASH_SOURCE})/split1_bash.sh" \; \
	split-window -d "$(dirname $BASH_SOURCE)/split1_gadget.sh" \; \
	attach \; \
	select-pane -D \;
