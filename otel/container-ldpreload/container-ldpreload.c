#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <libgen.h>


static void __myinit(void) __attribute__((constructor));
static void __myinit(void)
{
	// only pid 1
	if (getpid() != 1)
		return;

	char *previous = getenv("PYTHONPATH");
	const char *new_path = "/opt/oteltracepy/lib/python3.7/site-packages";

	if (previous == NULL || strlen(previous) == 0) {
		setenv("PYTHONPATH", new_path, 1);
		return;
	}

	// skip if already done
	if (strstr(previous, new_path))
		return;

	char buf[1024] = {0,};
	snprintf(buf, sizeof(buf), "%s:%s", new_path, previous);
	setenv("PYTHONPATH", buf, 1);
}
