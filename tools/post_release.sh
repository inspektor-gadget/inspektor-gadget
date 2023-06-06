#!/bin/bash

set -ex;

MINIKUBE_PATH='/tmp/minikube'
VSCODE_PATH='/tmp/vscode-aks-tools'
WEBSITE_PATH='/tmp/website'

function do_pr {
	local branch
	local msg
	local release
	local base
	local remote
	local human

	if [ $# -lt 6 ]; then
		echo "${FUNCNAME[0]} needs 6 arguments: branch_name, pr_msg, release, base_branch, remote and github_account" 1>&2

		exit 1
	fi

	branch=$1
	msg=$2
	release=$3
	base=$4
	remote=$5
	human=$6

	git checkout $base
	git pull
	git checkout -b $branch
	git add -u .
	git commit -s -m "$msg"

	gh auth login --with-token
	gh pr create \
		--body "$(printf "$(cat << EOF
Hi.


This PR bumps Inspektor Gadget to the latest release, _i.e._ %s.


Best regards and thank you in advance.

P.S.: This PR was opened by a script to deal with post release jobs.
In case of problem or review, @%s will deal with it.
EOF
)" $release $human)" \
		--title "$msg" \
		--head "$branch" \
		--base "$base"
}

function get_digest {
	local release_tag

	if [ $# -lt 1 ]; then
		echo "${FUNCNAME[0]} needs one argument: the release_tag" 1>&2

		exit 1
	fi

	release_tag=$1

	token=$(curl --silent https://ghcr.io/token\?scope\="repository:inspektor-gadget/inspektor-gadget:pull" | jq .token | tr -d '"')

	curl --silent --head -H "Authorization: Bearer ${token}" https://ghcr.io/v2/inspektor-gadget/inspektor-gadget/manifests/$release_tag | grep 'docker-content-digest' | cut -d':' -f3
}

function minikube {
	local release_yaml_path
	local human

	if [ $# -lt 2 ]; then
		echo "${FUNCNAME[0]} needs two arguments: the release_yaml_path and github_account" 1>&2

		exit 1
	fi

	release_yaml_path=$1
	human=$2

	perl split-release-yaml.pl $release_yaml_path

	cp ig-* $MINIKUBE_PATH/deploy/addons/inspektor-gadget

	export release="v0.17.0"
	export hash=$(get_digest $release)

	pushd $MINIKUBE_PATH

	perl -pi -e 's#(inspektor-gadget/inspektor-gadget:)v\d+\.\d+\.\d+(@sha256:)\w+#$1$ENV{release}$2$ENV{hash}#' pkg/minikube/assets/addons.go

	do_pr "update-ig-addon-${release}" "addon: Bump Inspektor Gadget addon to ${release}" "$release" 'master' 'origin' "$human"

	unset release
	unset hash

	popd
}

function vscode {
	local human

	if [ $# -lt 1 ]; then
		echo "${FUNCNAME[0]} needs one argument: the github_account" 1>&2

		exit 1
	fi

	human=$1

	export release="v0.17.0"

	pushd $VSCODE_PATH

	perl -pi -e 's/v\d+\.\d+\.\d+/$ENV{release}/' package.json

	do_pr "update-kubectl-gadget-${release}" "Update config to use kubectl-gadget ${release}" 'master' 'origin' "$human"

	unset release

	popd
}

function website {
	local human

	if [ $# -lt 1 ]; then
		echo "${FUNCNAME[0]} needs one argument: the github_account" 1>&2

		exit 1
	fi

	human=$1

	export release="v0.17.0"

	pushd $WEBSITE_PATH

	perl -pi -e 's/v\d+\.\d+\.\d+/$ENV{release}/' config.yaml

	do_pr "add-docs-${release}" "add ${release} docs" "$release" 'main' 'origin' "$human"

	unset release

	popd
}

if [ $# -lt 2 ]; then
	echo "$0 needs two arguments: the release_yaml_path and github_account" 1>&2

	exit 1
fi

if [ -z "${GH_TOKEN}" ]; then
	echo "$0 needs GH_TOKEN to be set in env" 1>&2

	exit 1
fi

minikube $1 $2
website $2
vscode $2
