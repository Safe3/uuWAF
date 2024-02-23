#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <syslog.h>
#include "php.h"
#include "SAPI.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "pidm.h"

ZEND_DECLARE_MODULE_GLOBALS(pidm)

zend_module_entry pidm_module_entry = {
	STANDARD_MODULE_HEADER_EX, NULL,
	NULL,
	"pidm",
	NULL,
	PHP_MINIT(pidm),
	PHP_MSHUTDOWN(pidm),
	PHP_RINIT(pidm),
	PHP_RSHUTDOWN(pidm),
	PHP_MINFO(pidm),
	PHP_PIDM_VERSION,
	PHP_MODULE_GLOBALS(pidm),
	NULL,
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

static zval *pidm_get_zval_ptr(zend_execute_data *execute_data, int op_type, znode_op op) /* {{{ */ {
	zval *ret = EX_VAR(op.var);
	if (op_type & (IS_TMP_VAR|IS_VAR)) {
		ZVAL_DEREF(ret);		
	} else if (op_type == IS_CONST) {
		return EX_CONSTANT(op);
	} else if (op_type == IS_CV) {
		if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
			return NULL;
		}
		ZVAL_DEREF(ret);
	} else {
		return NULL;
	}
	return ret;
}

static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static ssize_t b64dec_len(const char *bufcoded)
{
    ssize_t nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

static ssize_t b64dec(char *bufplain, const char *bufcoded)
{
    ssize_t nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

static const char basis_64[] ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static ssize_t b64enc_len(ssize_t len)
{
    return ((len + 2) / 3 * 4) + 1;
}

static ssize_t b64enc(char *encoded, const char *string, ssize_t len)
{
    ssize_t i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    *p++ = basis_64[((string[i] & 0x3) << 4) |
                    ((int) (string[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                    ((int) (string[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
        *p++ = basis_64[((string[i] & 0x3) << 4)];
        *p++ = '=';
    }
    else {
        *p++ = basis_64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}

char *enc(const char *src)
{
		char *str;
        ssize_t len;
        
        len = strlen(src);
        if(!len)return NULL;
        len = b64enc_len(len);
        str = emalloc(len);
		if (str == NULL) {
			return NULL;
		}
		b64enc(str,src,strlen(src));
        return str;
}

static int pidm_log(int level,char *func,const char *format, ...) /* {{{ */ {
	char *buffer, *msg, *start, *end, *ip, *b1, *b2;
	va_list args;
	const char *filename;
	uint lineno = 0;
	size_t len;
	int ret;
	zval *z_ip;

	va_start(args, format);
	vspprintf(&buffer, 0, format, args);
	spprintf(&msg, 0, "%s", buffer);
	efree(buffer);
	
	ip = NULL;
	
	if ((Z_TYPE(PG(http_globals)[TRACK_VARS_SERVER]) == IS_ARRAY || zend_is_auto_global_str(ZEND_STRL("_SERVER"))) &&
		(z_ip = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]), "REMOTE_ADDR", sizeof("REMOTE_ADDR")-1)) != NULL &&
		Z_TYPE_P(z_ip) == IS_STRING) {
		ip = Z_STRVAL_P(z_ip);
	}

	if (zend_is_compiling()) {
		filename = ZSTR_VAL(zend_get_compiled_filename());
		lineno = zend_get_compiled_lineno();
	} else if (zend_is_executing()) {
		filename = zend_get_executed_filename();
		if (filename[0] == '[') { /* [no active file] */
			filename = NULL;
			lineno = 0;
		} else {
			lineno = zend_get_executed_lineno();
		}
	} else {
		filename = NULL;
		lineno = 0;
	}
	len = 0;
	if (!filename) {
		filename = "Unknown";
	} else {
		start = end = strstr(filename,") : ");
		if (start) {
			while (start > filename) {
				if (*start == '(') {
					break;
				}
				start--;
			}
			len = start - filename;
			if (len) {				
				start = strdup(filename);
				*(start + len) = 0;
				*(start + (end - filename)) = 0;
				if(PIDM_G(level) < 5){
					level = 4;
					b1 = enc(start);
					b2 = enc(msg);
					syslog(LOG_ALERT,"php-log{level:4,ip:%s,path:%s,line:%s,func:%s,arg:%s}\n",ip,b1,start + len + 1,func,b2);
					if(b1) efree(b1);
					if(b2) efree(b2);
				}				
				free(start);
			}
		}
	}
	
	if (!len && level > PIDM_G(level)) {
		b1 = enc(filename);
		b2 = enc(msg);
		syslog(LOG_ALERT,"php-log{level:%d,ip:%s,path:%s,line:%d,func:%s,arg:%s}\n",level,ip,b1,lineno,func,b2);
		if(b1) efree(b1);
		if(b2) efree(b2);
	}
	
	efree(msg);
	va_end(args);
		
	if(PIDM_G(defence) && level > PIDM_G(level)){
		return ZEND_USER_OPCODE_RETURN;
	}
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int pidm_evil_zstr(zend_string *zstr) /* {{{ */ {
	if (zend_string_equals_literal(zstr, "assert") ||
		zend_string_equals_literal(zstr, "preg_replace") ||
		zend_string_equals_literal(zstr, "passthru") ||
		zend_string_equals_literal(zstr, "system") ||
		zend_string_equals_literal(zstr, "exec") ||
		zend_string_equals_literal(zstr, "shell_exec") ||
		zend_string_equals_literal(zstr, "proc_open") ||
		zend_string_equals_literal(zstr, "pcntl_exec") ||
		zend_string_equals_literal(zstr, "popen")) {
		return 1;
	}
	return 0;
} /* }}} */
	
static int pidm_init_dynamic_fcall_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zval *op2,*cname,*mname;
	zend_string *fname;
	zend_array *arr;

	op2 = pidm_get_zval_ptr(execute_data, opline->op2_type, opline->op2);

	if (op2) {
		if (IS_STRING == Z_TYPE_P(op2)) {
			fname = Z_STR_P(op2);
			if(pidm_evil_zstr(fname)){
				return pidm_log(4,"dynamic",Z_STRVAL_P(op2));
			}			
		} else if (IS_ARRAY == Z_TYPE_P(op2)&&(arr=Z_ARRVAL_P(op2))) {
			if(arr->nNumOfElements==1){//array('assert')($_POST[2])
				mname = zend_hash_index_find(Z_ARRVAL_P(op2), 0);
				if (mname && IS_STRING == Z_TYPE_P(mname)&&pidm_evil_zstr(Z_STR_P(mname))) {
					return pidm_log(4,"dynamic",Z_STRVAL_P(mname));
				}
			} else if(arr->nNumOfElements==2){//array('Foo','f')($_POST[2])
				cname = zend_hash_index_find(Z_ARRVAL_P(op2), 0);
				mname = zend_hash_index_find(Z_ARRVAL_P(op2), 1);
				if (cname && IS_STRING == Z_TYPE_P(cname) && mname && IS_STRING == Z_TYPE_P(mname)) {
					//pidm_log("dynamic3//%s::%s//4",Z_STRVAL_P(cname),Z_STRVAL_P(mname));
				}
			}			
		}
	}
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int pidm_include_or_eval_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zval *op1;

	op1 = pidm_get_zval_ptr(execute_data, opline->op1_type, opline->op1);

	if (op1 && IS_STRING == Z_TYPE_P(op1)) {
		switch (opline->extended_value) {
			case ZEND_INCLUDE_ONCE:
			case ZEND_REQUIRE_ONCE:
			case ZEND_INCLUDE:
			case ZEND_REQUIRE:
				if(Z_STRLEN_P(op1)>0&&(!(strcmp(Z_STRVAL_P(op1)+Z_STRLEN_P(op1)-4,".php")==0)||strstr(Z_STRVAL_P(op1),"://")))
				return pidm_log(4,"include",Z_STRVAL_P(op1));
				break;
			case ZEND_EVAL:
				if (Z_STRLEN_P(op1) > 128) {
					return pidm_log(3,"eval",Z_STRVAL_P(op1));
				} else {
					return pidm_log(2,"eval",Z_STRVAL_P(op1));
				}				
				break;
		}
	}

	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static char *stristr(char *String, char *Pattern)
{
      char *pptr, *sptr, *start;
      uint  slen, plen;

      for (start = String,pptr  = Pattern,slen  = strlen(String),plen  = strlen(Pattern);slen >= plen;start++, slen--)
      {
            while (toupper(*start) != toupper(*Pattern))
            {
                  start++;
                  slen--;
                  if (slen < plen) return NULL;
            }
            sptr = start;
            pptr = Pattern;

            while (toupper(*sptr) == toupper(*pptr))
            {
                  sptr++;
                  pptr++;
                  if ('\0' == *pptr) return start;
            }
      }
      return NULL;
}

static int pidm_fcall_check(zend_execute_data *ex,  zend_function *func) /* {{{ */ {
	zval *arg1, *arg2;
	zend_string *cname, *fname;
	int seconds;
	
	int arg_count = ZEND_CALL_NUM_ARGS(ex);
	
	fname = func->common.function_name;
	//printf("%s\n",ZSTR_VAL(fname));

	if (arg_count) {
		if (func->common.scope == NULL) {
			if (zend_string_equals_literal(fname, "passthru") ||
					zend_string_equals_literal(fname, "system") ||
					zend_string_equals_literal(fname, "exec") ||
					zend_string_equals_literal(fname, "shell_exec") ||
					zend_string_equals_literal(fname, "proc_open") ||
					zend_string_equals_literal(fname, "pcntl_exec") ||
					zend_string_equals_literal(fname, "popen")) {
				arg1 = ZEND_CALL_ARG(ex, 1);
				if (IS_STRING == Z_TYPE_P(arg1)) {
					return pidm_log(3,ZSTR_VAL(fname),Z_STRVAL_P(arg1));
				}			
			} else if (zend_string_equals_literal(fname, "opendir")) {
				arg1 = ZEND_CALL_ARG(ex, 1);
				if (IS_STRING == Z_TYPE_P(arg1)) {
					return pidm_log(2,ZSTR_VAL(fname),Z_STRVAL_P(arg1));
				}			
			} else if (zend_string_equals_literal(fname, "glob") ||
					zend_string_equals_literal(fname, "dir") ||
					zend_string_equals_literal(fname, "scandir")) {
				arg1 = ZEND_CALL_ARG(ex, 1);
				if (IS_STRING == Z_TYPE_P(arg1)) {
					return pidm_log(1,ZSTR_VAL(fname),Z_STRVAL_P(arg1));
				}			
			} else if (zend_string_equals_literal(fname, "set_time_limit")) {
				arg1 = ZEND_CALL_ARG(ex, 1);
				if (IS_LONG == Z_TYPE_P(arg1)) {
					seconds = Z_LVAL_P(arg1);
					if (seconds == 0 || seconds > 360) {
						return pidm_log(2,ZSTR_VAL(fname), "%d", seconds);
					}				
				}			
			} else if (zend_string_equals_literal(fname, "ini_set") && arg_count == 2) {
				arg1 = ZEND_CALL_ARG(ex, 1);
				arg2 = ZEND_CALL_ARG(ex, 2);
				if (IS_STRING == Z_TYPE_P(arg1) && zend_string_equals_literal(Z_STR_P(arg1), "max_execution_time")) {
					if (IS_LONG == Z_TYPE_P(arg2)) {
						seconds = Z_LVAL_P(arg2);
						if (seconds == 0 || seconds > 360) {
							return pidm_log(2,ZSTR_VAL(fname), "max_execution_time %d", seconds);
						}				
					} else if (IS_STRING == Z_TYPE_P(arg2)) {
						seconds = atoi(Z_STRVAL_P(arg2));
						if (seconds == 0 || seconds > 360) {
							return pidm_log(2,ZSTR_VAL(fname), "max_execution_time %d", seconds);
						}
					}					
				}			
			} else if (zend_string_equals_literal(fname, "move_uploaded_file") && arg_count == 2) {
				arg2 = ZEND_CALL_ARG(ex, 2);
				if (IS_STRING == Z_TYPE_P(arg2)) {
					if(stristr(Z_STRVAL_P(arg2),".php") || !strcmp(Z_STRVAL_P(arg2),".user.ini") || !strcmp(Z_STRVAL_P(arg2),".htaccess")) return pidm_log(4,ZSTR_VAL(fname),Z_STRVAL_P(arg2));
				}			
			} else if ((zend_string_equals_literal(fname, "fsockopen") || zend_string_equals_literal(fname, "pfsockopen")) && arg_count > 1) {
				arg1 = ZEND_CALL_ARG(ex, 1);
				arg2 = ZEND_CALL_ARG(ex, 2);
				if (IS_STRING == Z_TYPE_P(arg1) && IS_LONG == Z_TYPE_P(arg2)) {
					return pidm_log(2,ZSTR_VAL(fname), "%s %d", Z_STRVAL_P(arg1),Z_LVAL_P(arg2));									
				}			
			} else if ((zend_string_equals_literal(fname, "socket_connect") || zend_string_equals_literal(fname, "socket_bind")) && arg_count > 2) {
				arg1 = ZEND_CALL_ARG(ex, 2);
				arg2 = ZEND_CALL_ARG(ex, 3);
				if (IS_STRING == Z_TYPE_P(arg1) && IS_LONG == Z_TYPE_P(arg2)) {
					return pidm_log(2,ZSTR_VAL(fname), "%s %d", Z_STRVAL_P(arg1),Z_LVAL_P(arg2));									
				}			
			} else if (zend_string_equals_literal(fname, "stream_socket_client") || zend_string_equals_literal(fname, "stream_socket_server")) {
				arg1 = ZEND_CALL_ARG(ex, 1);
				if (IS_STRING == Z_TYPE_P(arg1)) {
					return pidm_log(2,ZSTR_VAL(fname), Z_STRVAL_P(arg1));									
				}			
			}			
		} else {
			cname = func->common.scope->name;
			printf("%s\n",ZSTR_VAL(cname));
			if (zend_string_equals_literal(cname, "ReflectionFunction")) {
				if (zend_string_equals_literal(fname, "__construct")) {
					arg1 = ZEND_CALL_ARG(ex, 1);					
					if (IS_STRING == Z_TYPE_P(arg1)&&pidm_evil_zstr(Z_STR_P(arg1))) {
						return pidm_log(4,"ReflectionFunction",Z_STRVAL_P(arg1));
					}
				}
			} else if (zend_string_equals_literal(cname, "DirectoryIterator")) {
				if (zend_string_equals_literal(fname, "__construct")) {
					arg1 = ZEND_CALL_ARG(ex, 1);					
					if (IS_STRING == Z_TYPE_P(arg1)) {
						return pidm_log(1,"DirectoryIterator",Z_STRVAL_P(arg1));
					}
				}
			} else if (zend_string_equals_literal(cname, "FilesystemIterator")) {
				if (zend_string_equals_literal(fname, "__construct")) {
					arg1 = ZEND_CALL_ARG(ex, 1);					
					if (IS_STRING == Z_TYPE_P(arg1)) {
						return pidm_log(1,"FilesystemIterator",Z_STRVAL_P(arg1));
					}
				}
			} else if (zend_string_equals_literal(cname, "GlobIterator")) {
				if (zend_string_equals_literal(fname, "__construct")) {
					arg1 = ZEND_CALL_ARG(ex, 1);					
					if (IS_STRING == Z_TYPE_P(arg1)) {
						return pidm_log(1,"GlobIterator",Z_STRVAL_P(arg1));
					}
				}
			}
		}
		
	} else if (func->common.scope == NULL) {
		if (zend_string_equals_literal(fname, "phpinfo")) {
			return pidm_log(2,ZSTR_VAL(fname), "(null)");			
		}
	}
	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static int pidm_fcall_handler(zend_execute_data *execute_data) /* {{{ */ {
	const zend_op *opline = execute_data->opline;
	zend_execute_data *call = execute_data->call;
	zend_function *func = call->func;

	if (func->type == ZEND_INTERNAL_FUNCTION) {
		return pidm_fcall_check(call, func);
	}

	return ZEND_USER_OPCODE_DISPATCH;
} /* }}} */

static void pidm_register_handlers() /* {{{ */ {
	zend_set_user_opcode_handler(ZEND_INIT_USER_CALL, pidm_init_dynamic_fcall_handler);
	zend_set_user_opcode_handler(ZEND_INIT_DYNAMIC_CALL, pidm_init_dynamic_fcall_handler);
	zend_set_user_opcode_handler(ZEND_INCLUDE_OR_EVAL, pidm_include_or_eval_handler);
	zend_set_user_opcode_handler(ZEND_DO_FCALL, pidm_fcall_handler);
	zend_set_user_opcode_handler(ZEND_DO_ICALL, pidm_fcall_handler);
	zend_set_user_opcode_handler(ZEND_DO_FCALL_BY_NAME, pidm_fcall_handler);
} /* }}} */

#ifdef COMPILE_DL_PIDM
ZEND_GET_MODULE(pidm)
#endif

static PHP_INI_MH(OnUpdateLevel) /* {{{ */ {
	if (!new_value) {
		PIDM_G(level) = 0;
	} else {
		PIDM_G(level) = (int)atoi(ZSTR_VAL(new_value));
	}
	return SUCCESS;
} /* }}} */

/* {{{ PHP_INI
*/
PHP_INI_BEGIN()
	STD_PHP_INI_BOOLEAN("pidm.enable", "1", PHP_INI_SYSTEM, OnUpdateBool, enable, zend_pidm_globals, pidm_globals)
	STD_PHP_INI_ENTRY("pidm.level", "0", PHP_INI_SYSTEM, OnUpdateLevel, level, zend_pidm_globals, pidm_globals)
	STD_PHP_INI_BOOLEAN("pidm.defence", "0", PHP_INI_SYSTEM, OnUpdateBool, defence, zend_pidm_globals, pidm_globals)
PHP_INI_END()
	/* }}} */

PHP_MINIT_FUNCTION(pidm)
{
	REGISTER_INI_ENTRIES();

	if (!PIDM_G(enable)) {
		return SUCCESS;
	}

	pidm_register_handlers();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
*/
PHP_MSHUTDOWN_FUNCTION(pidm)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION
*/
PHP_RINIT_FUNCTION(pidm)
{
	
	if (SG(sapi_started)) {
		return SUCCESS;
	}
		
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION
*/
PHP_RSHUTDOWN_FUNCTION(pidm)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
*/
PHP_MINFO_FUNCTION(pidm)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "pidm support", "enabled");
	php_info_print_table_row(2, "Version", PHP_PIDM_VERSION);
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */