#!/bin/bash
set -e -x

# Python 3 is needed to build ECDAA, so add it
# to global PTH
export PATH=$PATH:$(find find /opt/_internal -maxdepth 1 -name 'cpython-3.6.*' -type d)/bin

# CMake is needed for all deps, so install it
pip3 install cmake

# Preserve dist
if [ -d dist ]; then mv dist tmpdist; fi

# Compile wheels
for PYBIN in /opt/python/*/bin; do
    # Build the wheel
    "${PYBIN}"/pip install -r requirements/setup.txt
    "${PYBIN}"/python setup.py bdist_wheel
    rm -rf .eggs
done

# Bundle external shared libraries into the wheels
for whl in dist/*.whl; do
    auditwheel repair "$whl" -w tmpdist/
done

# Install packages and test
for PYBIN in /opt/python/*/bin; do
    "${PYBIN}"/pip install -r requirements/prod.txt
    "${PYBIN}/pip" install xtt --no-index -f tmpdist/

    "${PYBIN}"/pip install -r requirements/test.txt
    pushd "$HOME"; "${PYBIN}/nosetests" xtt; popd
done

# Restore dist
rm -rf dist && mv tmpdist dist
