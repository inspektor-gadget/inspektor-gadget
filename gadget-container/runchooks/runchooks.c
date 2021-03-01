// Copyright 2019-2021 The Inspektor Gadget authors
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static void __myinit(void) __attribute__((constructor));
static void __myinit(void)
{
	// ignore non-root programs
	if (geteuid() != 0)
		return;

	// ignore non-runc programs
	char buf[1024] = {0,};
	int ret;
	ret = readlink("/proc/self/exe", buf, sizeof(buf));
	if (ret <= 0 || ret == sizeof(buf))
		return;
	char *b = basename(buf);
	if (strcmp(b, "runc") != 0) {
		return;
	}

	// find the bundle directory in the command line
	FILE *cmdline = fopen("/proc/self/cmdline", "r");
	char *arg = 0;
	size_t size = 0;
	int create_found = 0;
	int next = 0;
	char *bundledir = NULL;
	while(getdelim(&arg, &size, 0, cmdline) != -1) {
		if (strcmp("create", arg) == 0) {
			create_found = 1;
			continue;
		}
		if (create_found && strcmp("--bundle", arg) == 0) {
			next = 1;
			continue;
		}
		if (next) {
			bundledir = strdup(arg);
			break;
		}
	}
	free(arg);
	fclose(cmdline);

	// ignore runc programs for other verbs than 'create'
	if (!create_found)
		return;

	// ignore runc programs without bundle directory
	if (bundledir == NULL)
		return;

	char cmd[1024] = {0,};

	ret = snprintf(cmd, sizeof(cmd), "cd %s && cp config.json config.json.orig && cat config.json.orig | jq -r \". * `cat /opt/runchooks/add-hooks.jq`\" > config.json", bundledir);
	free(bundledir);
	if (ret < sizeof(cmd))
		system(cmd);
}
