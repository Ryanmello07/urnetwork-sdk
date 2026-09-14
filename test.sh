#!/usr/bin/env zsh

# root sdk module
go test -timeout 0 -v -race "$@"
if [[ $? != 0 ]]; then
    exit 1
fi

# submodules with their own go.mod (cgo, js, build): run each module's go
# tests from inside the module, the way server/test.sh iterates its test
# dirs. Only modules that contain _test.go files are run — the js/build
# modules target wasm and do not build for the host. Notably cgo/gen holds
# the ABI baseline test, which must run from the cgo module.
for mod in `find . -mindepth 2 -maxdepth 2 -name go.mod | xargs -n 1 dirname | sort`; do
    if [[ -z `find $mod -name '*_test.go' -not -path '*/node_modules/*' -print -quit` ]]; then
        continue
    fi
    # A module whose `replace` targets a directory that is not checked out CANNOT be built, and
    # `go test` in it fails with "replacement directory ... does not exist" -- which used to
    # `exit $result` and take the whole sweep down. cp3b requires
    # github.com/urnetwork/message-server, which is a DIFFERENT REPOSITORY that a checkout of sdk
    # does not bring with it, so that is not a broken tree: it is the ordinary state of anyone who
    # has not also cloned the server.
    #
    # IT IS SKIPPED WITH A PRINTED LINE AND NEVER SILENTLY. A sweep that quietly dropped a module
    # would make "cp3b was not run" and "cp3b passed" the same output, which is the exact shape
    # this project keeps finding in gates.
    missing=""
    for target in `grep -E '=>[[:space:]]+\.{1,2}/' $mod/go.mod | sed -E 's|.*=>[[:space:]]+([^[:space:]]+).*|\1|'`; do
        if [[ ! -d $mod/$target ]]; then
            missing="$missing $target"
        fi
    done
    if [[ -n $missing ]]; then
        echo "SKIPPING $mod: its go.mod replaces$missing, which is not checked out beside this repo."
        echo "  Clone it under its own name (github.com/urnetwork/message-server => ../message-server)"
        echo "  as a sibling of sdk, and this module runs. NOTHING IN $mod WAS TESTED."
        continue
    fi
    pushd $mod
    go test -timeout 0 -v -race "$@" ./...
    result=$?
    popd
    if [[ $result != 0 ]]; then
        exit $result
    fi
done

# js package tests (node --test via the package script): fetch_retry + the
# wasm surface guard
if [[ -f js/package.json ]]; then
    pushd js
    npm test
    result=$?
    popd
    if [[ $result != 0 ]]; then
        exit $result
    fi
fi

# ./test.sh -run 'pattern' (applies to the go modules; npm test ignores it)
