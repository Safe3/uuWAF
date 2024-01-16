dnl $Id$

PHP_ARG_ENABLE(pidm, whether to enable pidm support,
[  --enable-pidm           Enable pidm support])

if test "$PHP_PIDM" != "no"; then
  PHP_NEW_EXTENSION(pidm, pidm.c, $ext_shared)
fi
