#ifndef PHP_PIDM_H
#define PHP_PIDM_H

extern zend_module_entry pidm_module_entry;
#define phpext_pidm_ptr &pidm_module_entry

#ifdef PHP_WIN32
#define PHP_PIDM_API __declspec(dllexport)
#else
#define PHP_PIDM_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#define PHP_PIDM_VERSION "1.0.3"

#if PHP_VERSION_ID > 70000 
# if PHP_VERSION_ID < 70100
# define PHP_7_0  1
# define PHP_7_1  0
# elif PHP_VERSION_ID < 70200
# define PHP_7_0  0
# define PHP_7_1  1
# else
# error "Unsupported PHP Version ID:" PHP_VERSION_ID
# endif
#else
# error "Unsupported PHP Version ID:" PHP_VERSION_ID
#endif

typedef zval* pidm_free_op;

PHP_MINIT_FUNCTION(pidm);
PHP_MSHUTDOWN_FUNCTION(pidm);
PHP_RINIT_FUNCTION(pidm);
PHP_RSHUTDOWN_FUNCTION(pidm);
PHP_MINFO_FUNCTION(pidm);

ZEND_BEGIN_MODULE_GLOBALS(pidm)
	zend_bool enable;
	int       level;
	zend_bool defence;
ZEND_END_MODULE_GLOBALS(pidm)

#ifdef ZTS
#define PIDM_G(v) TSRMG(pidm_globals_id, zend_pidm_globals *, v)
#else
#define PIDM_G(v) (pidm_globals.v)
#endif

#endif	/* PHP_PIDM_H */