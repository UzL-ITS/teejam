#!/bin/bash

WOLFSSL_LINUX_BUILD_PATH=./wolfssl/IDE/LINUX-SGX

CFLAGS_NEW="-DWOLFSSL_AES_TOUCH_LINES"
export CFLAGS="${CFLAGS} ${CFLAGS_NEW}"
echo ${CFLAGS}

pushd ${WOLFSSL_LINUX_BUILD_PATH}

make -f sgx_t_static.mk HAVE_WOLFSSL_SP=1 all

popd

cp ${WOLFSSL_LINUX_BUILD_PATH}/libwolfssl.sgx.static.lib.a libwolfssl
