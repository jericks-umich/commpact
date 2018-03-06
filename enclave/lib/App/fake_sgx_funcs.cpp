
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <fake_sgx_funcs.h>

sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes) {
  int rand_handle = open("/dev/urandom", O_RDONLY);
  if (rand_handle < 0) {
    printf("Error opening /dev/urandom\n");
    return SGX_ERROR_UNEXPECTED;
  }
  ssize_t ret = read(rand_handle, rand, length_in_bytes);
  close(rand_handle);
  if (ret < 0) {
    printf("Error reading from /dev/urandom\n");
    return SGX_ERROR_UNEXPECTED;
  }
  return SGX_SUCCESS;
}

// The following code is included from the Intel SGX source code (memset_s.c)
// It is licensed under Intel's NetBSD License, included below.

/*-
 * Copyright (c) 2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alan Barrett
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * ISO/IEC 9899:2011 section K.3.7.4.1 The memset_s function
 */

#include <sys/cdefs.h>

#define __STDC_WANT_LIB_EXT1__ 1
#include <errno.h>
#include <stdint.h>
#include <string.h>

/*
 * __memset_vp is a volatile pointer to a function.
 * It is initialised to point to memset, and should never be changed.
 */
static void *(*const volatile __memset_vp)(void *, int, size_t) = (memset);

#undef memset_s /* in case it was defined as a macro */

errno_t memset_s(void *s, size_t smax, int c, size_t n) {
  errno_t err = 0;

  if (s == NULL) {
    err = EINVAL;
    goto out;
  }
  if (smax > SIZE_MAX) {
    err = E2BIG;
    goto out;
  }
  if (n > SIZE_MAX) {
    err = E2BIG;
    n = smax;
  }
  if (n > smax) {
    err = EOVERFLOW;
    n = smax;
  }

  /* Calling through a volatile pointer should never be optimised away. */
  (*__memset_vp)(s, c, n);

out:
  if (err == 0)
    return 0;
  else {
    errno = err;
    /* XXX call runtime-constraint handler */
    return err;
  }
}
