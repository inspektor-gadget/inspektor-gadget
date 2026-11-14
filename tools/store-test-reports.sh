#!/usr/bin/env bash

set +x

if [ -z "$GITHUB_ACTIONS" ]; then
  echo "This script is expected to run in a GitHub Action"
  exit 1
fi

function retry {
  local n=1
  local max=10
  local delay=15
  while true; do
    "$@" && break || {
      if [[ $n -lt $max ]]; then
        ((n++))
        echo "Command failed. Attempt $n/$max:"
        sleep $((RANDOM % delay))
      else
        echo "The command has failed after $n attempts."
        return 1
      fi
    }
  done
}

function store-reports {
  local dir=$(mktemp -d -p . --suffix -ig-test-reports)
  local repo="https://github.com/inspektor-gadget/ig-test-reports.git"

  git clone $repo $dir
  pushd $dir || exit 1
  if [ ! -d data ]; then
    mkdir -p data
    echo '{}' > data/workflows.json
  fi
  for i in ../test-reports-*-*/test-report_*_*.json; do
      job_key=$(basename $i .json | sed 's/test-report_//')
      jq --slurpfile obj $i \
      --arg job_key ${job_key} \
      '.[$job_key] = (.[$job_key][-99:] + $obj)' \
      data/workflows.json > workflows.json.tmp
      if [ ! -s workflows.json.tmp ]; then
        echo "Skipping empty file: $i" >&2
        rm workflows.json.tmp
        continue
      fi
      mv workflows.json.tmp data/workflows.json
  done

  git config --global user.email "github-actions[bot]@users.noreply.github.com"
  git config --global user.name "github-actions[bot]"
  git add data
  git commit -m "Add test reports for workflow ${GITHUB_RUN_NUMBER} and attempt ${GITHUB_RUN_ATTEMPT}"
  git push
  if [ $? -ne 0 ]; then
    popd || exit 1
    return 1
  fi
  popd || exit 1
}

# Pass the token in a header rather than in the URL: since the curl security
# updates in the 20261018 runner images, git drops the credentials of the URL
# ("warning: redirecting to ...") and the push fails with "could not read
# Username".
auth=$(printf 'x-access-token:%s' "$TEST_REPORTS_TOKEN" | base64 -w0)
echo "::add-mask::$auth"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="http.https://github.com/.extraheader"
export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $auth"

retry store-reports
rc=$?
rm -rf *-ig-test-reports
exit $rc
