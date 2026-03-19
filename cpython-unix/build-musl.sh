#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -ex

cd /build

export PATH=/tools/${TOOLCHAIN}/bin:/tools/host/bin:$PATH
export CC=clang

tar -xf "musl-${MUSL_VERSION}.tar.gz"

pushd "musl-${MUSL_VERSION}"

# Debian as of at least bullseye ships musl 1.2.1. musl 1.2.2
# added reallocarray(), which gets used by at least OpenSSL.
# Here, we disable this single function so as to not introduce
# symbol dependencies on clients using an older musl version.
if [ "${MUSL_VERSION}" = "1.2.2" ]; then
    patch -p1 <<EOF
diff --git a/include/stdlib.h b/include/stdlib.h
index b54a051f..194c2033 100644
--- a/include/stdlib.h
+++ b/include/stdlib.h
@@ -145,7 +145,6 @@ int getloadavg(double *, int);
 int clearenv(void);
 #define WCOREDUMP(s) ((s) & 0x80)
 #define WIFCONTINUED(s) ((s) == 0xffff)
-void *reallocarray (void *, size_t, size_t);
 #endif

 #ifdef _GNU_SOURCE
diff --git a/src/malloc/reallocarray.c b/src/malloc/reallocarray.c
deleted file mode 100644
index 4a6ebe46..00000000
--- a/src/malloc/reallocarray.c
+++ /dev/null
@@ -1,13 +0,0 @@
-#define _BSD_SOURCE
-#include <errno.h>
-#include <stdlib.h>
-
-void *reallocarray(void *ptr, size_t m, size_t n)
-{
-	if (n && m > -1 / n) {
-		errno = ENOMEM;
-		return 0;
-	}
-
-	return realloc(ptr, m * n);
-}
EOF
else
    # There is a different patch for newer musl versions, used in static distributions
    patch -p1 <<EOF
diff --git a/include/stdlib.h b/include/stdlib.h
index b507ca3..8259e27 100644
--- a/include/stdlib.h
+++ b/include/stdlib.h
@@ -147,7 +147,6 @@ int getloadavg(double *, int);
 int clearenv(void);
 #define WCOREDUMP(s) ((s) & 0x80)
 #define WIFCONTINUED(s) ((s) == 0xffff)
-void *reallocarray (void *, size_t, size_t);
 void qsort_r (void *, size_t, size_t, int (*)(const void *, const void *, void *), void *);
 #endif

diff --git a/src/malloc/reallocarray.c b/src/malloc/reallocarray.c
deleted file mode 100644
index 4a6ebe4..0000000
--- a/src/malloc/reallocarray.c
+++ /dev/null
@@ -1,13 +0,0 @@
-#define _BSD_SOURCE
-#include <errno.h>
-#include <stdlib.h>
-
-void *reallocarray(void *ptr, size_t m, size_t n)
-{
-	if (n && m > -1 / n) {
-		errno = ENOMEM;
-		return 0;
-	}
-
-	return realloc(ptr, m * n);
-}
EOF
fi

# PYSTANDALONE: change fork call to always use clone
if [ "${MUSL_VERSION}" = "1.2.2" ]; then
    patch -p1 <<EOF
diff --git a/src/process/_Fork.c b/src/process/_Fork.c
index da06386..10691fa 100644
--- a/src/process/_Fork.c
+++ b/src/process/_Fork.c
@@ -6,6 +6,9 @@
 #include "pthread_impl.h"
 #include "aio_impl.h"

+#define CLONE_CHILD_CLEARTID   0x00200000
+#define CLONE_CHILD_SETTID     0x01000000
+
 static void dummy(int x) { }
 weak_alias(dummy, __aio_atfork);

@@ -16,11 +16,7 @@ pid_t _Fork(void)
	__block_all_sigs(&set);
	__aio_atfork(-1);
	LOCK(__abort_lock);
-#ifdef SYS_fork
-	ret = __syscall(SYS_fork);
-#else
-	ret = __syscall(SYS_clone, SIGCHLD, 0);
-#endif
+	ret = __syscall(SYS_clone, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, NULL, &__pthread_self()->tid);
	if (!ret) {
		pthread_t self = __pthread_self();
		self->tid = __syscall(SYS_gettid);
EOF
else
    patch -p1 <<EOF
diff --git a/src/process/_Fork.c b/src/process/_Fork.c
index 9c07792d..99b382c8 100644
--- a/src/process/_Fork.c
+++ b/src/process/_Fork.c
@@ -26,17 +26,16 @@ void __post_Fork(int ret)
	if (!ret) __aio_atfork(1);
 }

+#define CLONE_CHILD_CLEARTID   0x00200000
+#define CLONE_CHILD_SETTID     0x01000000
+
 pid_t _Fork(void)
 {
	pid_t ret;
	sigset_t set;
	__block_all_sigs(&set);
	LOCK(__abort_lock);
-#ifdef SYS_fork
-	ret = __syscall(SYS_fork);
-#else
-	ret = __syscall(SYS_clone, SIGCHLD, 0);
-#endif
+	ret = __syscall(SYS_clone, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0, NULL, &__pthread_self()->tid);
	__post_Fork(ret);
	__restore_sigs(&set);
	return __syscall_ret(ret);
EOF
fi

SHARED=
if [ -n "${STATIC}" ]; then
    SHARED="--disable-shared"
else
    SHARED="--enable-shared"
    CFLAGS="${CFLAGS} -fPIC" CPPFLAGS="${CPPFLAGS} -fPIC"
fi


CFLAGS="${CFLAGS}" CPPFLAGS="${CPPFLAGS}" ./configure \
    --prefix=/tools/host \
    "${SHARED}"

make -j "$(nproc)"
make -j "$(nproc)" install DESTDIR=/build/out

popd
