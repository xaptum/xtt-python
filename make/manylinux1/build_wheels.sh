#!/bin/bash
set -e -x

docker run \
       --rm \
       -v `pwd`:/xtt-python \
       -w /xtt-python \
       quay.io/pypa/manylinux1_x86_64 \
       bash -c "make/manylinux1/build.sh"

docker run \
       --rm \
       -v `pwd`:/xtt-python \
       -w /xtt-python \
       quay.io/pypa/manylinux1_i686 \
       bash -c "make/manylinux1/build.sh"
