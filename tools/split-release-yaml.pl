#! /usr/bin/env perl
# Copyright 2019-2023 The Inspektor Gadget authors
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
use strict;
use warnings;


my $yaml_path;
my $content;
my $kind;
my $line;
my $in_fd;

$yaml_path = shift or die "Usage: $0 path_to_release.yaml";

open $in_fd, '<', $yaml_path or die "Can not open ${yaml_path}: $!";
$content = '';

while ($line = <$in_fd>) {
	if ($line =~ m/^kind: (\w+)$/) {
		$kind = lc $1;
	}

	if ($line =~ m/---/) {
		my $out_fd;
		my $filename;

		$filename = "ig-${kind}.yaml";
		if ($kind eq 'daemonset') {
			$filename .= '.tmpl';
		}

		open $out_fd, '>', $filename or die "Can not open ${filename}: $!";

		print $out_fd $content;

		close $out_fd or warn "Problem while closing ${filename}: $!";

		$content = '';

		next;
	}

	$content .= $line;
}

close $in_fd or warn "Problem while closing ${yaml_path}: $!";
