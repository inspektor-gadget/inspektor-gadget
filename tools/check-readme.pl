#! /usr/bin/env perl
# Copyright 2019-2022 The Inspektor Gadget authors
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
use IPC::Open3;
use strict;
use warnings;


my $kubectl_gadget_path;
my $readme_path;
my $readme_line;
my $fd;

$kubectl_gadget_path = shift or die "Usage: $0 relative_path_to_kubectl_gadget path_to_README";
$readme_path = shift or die "Usage: $0 path_to_kubectl_gadget path_to_README";

if (substr($kubectl_gadget_path, 0, 1) ne '.') {
	die "kubectl-gadget must be relative path: ${kubectl_gadget_path}";
}

open $fd, '<', $readme_path or die "Can not open ${readme_path}: $!";

while ($readme_line = <$fd>) {
	my $exit_status;
	my @out_lines;
	my $out_line;
	my $out;
	my $err;
	my $pid;

	if ($readme_line !~ m/^\$ kubectl gadget (\w+)? ?--help$/) {
		next;
	}

	if (defined $1) {
		$pid = open3(undef, $out, $err, $kubectl_gadget_path, $1, '--help');
	} else {
		$pid = open3(undef, $out, $err, $kubectl_gadget_path, '--help');
	}

	waitpid $pid, 0;

	$exit_status = $! >> 8;
	if ($exit_status != 0) {
		my $err_output;
		my $err_line;

		close $fd or warn "Problem while closing ${readme_path}: $!";

		while ($err_line = <$err>) {
			$err_output .= $err_line;
		}

		die "Problem while running ${kubectl_gadget_path}: ${err_output}";
	}

	while ($out_line = <$out>) {
		chomp $out_line;

		$readme_line = <$fd>;
		chomp $readme_line;
		if ($readme_line =~ m/\.\.\./) {
			last;
		}

		if ($readme_line ne $out_line) {
			close $fd or warn "Problem while closing ${readme_path}: $!";

			die "Lines do not match: \"${out_line}\" != \"${readme_line}\"";
		}
	}
}

close $fd or warn "Problem while closing ${readme_path}: $!";
