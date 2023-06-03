#!/bin/sh
# SPDX-License-Identifier: GPL2-or-later
#
# Copyright (C) 2023 Olliver Schinagl <oliver@schinagl.nl>
#
# A beginning user should be able to docker run image bash (or sh) without
# needing to learn about --entrypoint
# https://github.com/docker-library/official-images#consistency

set -eu

bin='sslh'

# run command if it is not starting with a "-" and is an executable in PATH
if [ "${#}" -le 0 ] || \
   [ "${1#-}" != "${1}" ] || \
   [ -d "${1}" ] || \
   ! command -v "${1}" > '/dev/null' 2>&1; then
	entrypoint='true'
fi

exec ${entrypoint:+${bin}} "${@}"

exit 0
