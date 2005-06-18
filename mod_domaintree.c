/*
 * mod_domaintree.c - Apache2
 *
 * $Id$
 *
 * Copyright 2005 Michael Wallner <mike@iworks.at
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * <pre>
 * DomainTreeEnabled On
 * DomainTreeMaxdepth 25
 * DomainTreeStripWWW On
 * DomainTreePrefix /sites
 * DomainTreeSuffix /html
 * DomainTreeAliasRecursion Off
 * DomainTreeAlias /??/exmaple /com/exmaple
 * DomainTreeAlias /???/example /com/example
 * DomainTreeAlais /*one/ /anyone/
 *
 *	/sites
 *		+- /at
 *		|	+- /co
 *		|	|	+- /company
 *		|	|		+- /html
 *		|	|		+- /sub1
 *		|	|		|	+- /html
 *		|	|		+- /sub2
 *		|	|			+- /html
 *		|	+- /or
 *		|		+- /organisation
 *		|			+- /html
 *		+- /com
 *			+- /example
 *				+- /html
 * </pre>
 */

#define MODULE	"mod_domaintree"
#define AUTHOR	"mike@php.net"
#define VERSION "1.2"

/* {{{ Includes */

#include "httpd.h"
#include "http_config.h"

#define CORE_PRIVATE
#include "http_core.h"
#undef CORE_PRIVATE

#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr.h"
#include "apr_lib.h"
#include "apr_ring.h"
#include "apr_hash.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

/* }}} */
/* {{{ domaintree_module */

module AP_MODULE_DECLARE_DATA domaintree_module;

/* }}} */
/* {{{ Macros & Types */

#define MOD_DT_CNF domaintree_conf
#define MOD_DT_PTR (&domaintree_module)

#define NUL '\0'
#define EMPTY(str) ((str == NULL) || (*(str) == NUL))

#define DT_LOG_ERR ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, DT->server, 
#define DT_LOG_WRN ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, DT->server, 
#define DT_LOG_DBG ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, 
#define DT_LOG_END );

typedef int STATUS;

typedef struct {
	apr_hash_t	*hashtable;
	size_t		recursion;
} aliases_t;

typedef struct {
	server_rec	*server;
	int			enabled;
	int			stripwww;
	size_t		maxdepth;
	char		*prefix;
	char		*suffix;
	aliases_t	aliases;
} domaintree_conf;

struct domaintree_entry {
	char *name;
	APR_RING_ENTRY(domaintree_entry) link;
};
APR_RING_HEAD(domaintree, domaintree_entry);

/* }}} */
/* {{{ Helpers */

static APR_INLINE char *strtr(char *string, char from, char to)
{
	char *ptr = string;
	
	if (from != to) {
		while ((ptr = strchr(ptr, from))) {
			*ptr = to;
		}
	}
	return string;
}

static APR_INLINE char *trim(char *string, size_t length, char what, int l, int r)
{
	if (r) {
		while (length-- && (string[length] == what)) {
			string[length] = NUL;
		}
	}
	if (l) {
		while (*string == what) {
			++string;
		}
	}
	return string;
}

static APR_INLINE char *strcase(char *string, int case_type)
{
#ifndef CASE_LOWER
#	define CASE_LOWER 1
#endif
#ifndef CASE_UPPER
#	define CASE_UPPER 2
#endif

	char *ptr = string;
	
	switch (case_type)
	{
		case CASE_LOWER:
			while (*ptr) {
				apr_tolower(*ptr++);
			}
		break;
		
		case CASE_UPPER:
			while (*ptr) {
				apr_toupper(*ptr++);
			}
		break;
		
		default:
		break;
	}
	return string;
}

static APR_INLINE int strmatch(char *match, char *string, char **begin, char **end)
{
	*begin = *end = NULL;
	
	while (*match)
	{
		switch (*match)
		{
			case '*':
				while (*match == '*' || *match == '?') {
					++match;
				}
				
				if (!*begin) {
					*begin = string;
				}
				
				if (!*match) {
					*end = string + strlen(string);
					return 1;
				}
				
				if (!(string = strchr(string, *match))) {
					*end = string;
					return 0;
				}
			break;
			
			case '?':
				if (!*begin) {
					*begin = string;
				}
				++string;
				++match;
			break;
			
			default:
				if (*match == *string) {
					if (!*begin) {
						*begin = string;
					}
					++match;
				} else {
					if (*begin) {
						*end = string - 1;
						return 0;
					}
				}
				++string;
			break;
		}
	}
	
	*end = string;
	return 1;
}

static APR_INLINE char *struniqchr(char *string, char uniq)
{
	char *ptr = string;
	
	while (*ptr) {
		if (*ptr == uniq && *(ptr + 1) == uniq) {
			char *pos = ptr + 1;
			
			while (*(pos + 1) == uniq) {
				++pos;
			}
			
			memmove(ptr, pos, strlen(pos) + 1);
		}
		++ptr;
	}
	
	return string;
}

static APR_INLINE char *domaintree_host(apr_pool_t *pool, MOD_DT_CNF *DT, const char *name)
{
	if (EMPTY(name)) {
		DT_LOG_WRN
			"DomainTree: no host/server name"
		DT_LOG_END
		return NULL;
	} else {
		size_t len;
		char *port, *ptr, *host;
		
		ptr = host = apr_pstrdup(pool, name);
		
		DT_LOG_DBG
			"DomainTree: host name = %s", host
		DT_LOG_END
		
		/* check for :NN port */
		if ((port = strchr(ptr, ':'))) {
			len = port - ptr;
		} else {
			len = strlen(ptr);
		}
		
		/* strip leading & trailing dots, then lowercase */
		ptr = host = strcase(trim(ptr, len, '.', 1, 1), CASE_LOWER);
		
		DT_LOG_DBG
			"DomainTree: sane host = %s", host
		DT_LOG_END
		
		return host;
	}
}

static APR_INLINE const char *domaintree_elem(apr_pool_t *pool, struct domaintree *tree, const char *name, size_t length)
{
	struct domaintree_entry *elem = apr_palloc(pool, sizeof(struct domaintree_entry));
	
	APR_RING_ELEM_INIT(elem, link);
	APR_RING_INSERT_HEAD(tree, elem, domaintree_entry, link);
	
	return elem->name = apr_pstrndup(pool, name, length);
}

static APR_INLINE struct domaintree *domaintree_tree(apr_pool_t *pool, MOD_DT_CNF *DT, char *host)
{
	size_t depth = 0;
	char *host_ptr = host;
	struct domaintree *tree = apr_palloc(pool, sizeof(struct domaintree));
	
	APR_RING_INIT(tree, domaintree_entry, link);
	
	while ((host_ptr = strchr(host, '.'))) {
		
		/* check max depth */
		if (++depth > DT->maxdepth) {
			DT_LOG_ERR
				"DomainTree: maxdepth exceeded = %s", host
			DT_LOG_END
			return NULL;
		}
		
		/* append part */
		if (host_ptr - host) {
			
			/* strip WWW */
			if (DT->stripwww && (depth == 1) && (!strncmp(host, "www.", sizeof("www")))) {
				DT_LOG_DBG
					"DomainTree: stripping www."
				DT_LOG_END
			} else {
				DT_LOG_DBG
					"DomainTree: host part (%d) = %s", depth - 1, 
					domaintree_elem(pool, tree, host, host_ptr - host)
				DT_LOG_END
			}
		}
		
		host = host_ptr + 1;
	}
	
	/* append last part */
	if (!EMPTY(host)) {
		DT_LOG_DBG
			"DomainTree: host part (%d) = %s", depth, 
			domaintree_elem(pool, tree, host, strlen(host))
		DT_LOG_END
	}
	
	return tree;
}

static APR_INLINE char *domaintree_path(apr_pool_t *pool, MOD_DT_CNF *DT, struct domaintree *tree)
{
	struct domaintree_entry *elem;
	char *path = "";
	
	APR_RING_FOREACH(elem, tree, domaintree_entry, link) {
		path = apr_pstrcat(pool, path, "/", elem->name, NULL);
	}
	
	return path;
}

static APR_INLINE void domaintree_fake(apr_pool_t *pool, MOD_DT_CNF *DT, char **path)
{
	int more;
	apr_hash_index_t *idx;
	size_t recurlevel = 0;
	
	do {
		more = 0;
		
		if (recurlevel++ > DT->aliases.recursion) {
			DT_LOG_ERR
				"DomainTree: maximum alias recursion level (%d) exceeded! "
				"Check if you have recursive definitions of DomainTreeAlias directives.", 
				DT->aliases.recursion
			DT_LOG_END
			break;
		}
		
		for (idx = apr_hash_first(pool, DT->aliases.hashtable); idx; idx = apr_hash_next(idx)) {
			char *fake, *real, *begin, *end;
			
			apr_hash_this(idx, (const void **) &fake, NULL, (void **) &real);
			
			DT_LOG_DBG
				"DomainTree: fake test %s on %s", fake, *path
			DT_LOG_END
			
			if (strmatch(fake, *path, &begin, &end)) {
				*path = apr_pstrcat(pool, "/", apr_pstrndup(pool, *path, begin - *path), "/", real, "/", end, NULL);
				struniqchr(*path, '/');
				
				DT_LOG_DBG
					"DomainTree: fake done %s<>%s = %s", fake, real, *path
				DT_LOG_END
				
				more = 1;
			}
		}
	} while (more && DT->aliases.recursion);
}

/* }}} */
/* {{{ Hooks */

static STATUS domaintree_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	ap_add_version_component(pconf, MODULE "/" VERSION);
	return OK;
}

static STATUS domaintree_hook_translate_name(request_rec *r)
{
	MOD_DT_CNF *DT = NULL;
	struct domaintree *tree;
	char *path, *host;
	
	DT = ap_get_module_config(r->server->module_config, MOD_DT_PTR);
	if ((!DT) || (!DT->enabled)) {
		return DECLINED;
	}
	
	/* get a usable host name */
	if (!(host = domaintree_host(r->pool, DT, ap_get_server_name(r)))) {
		return DECLINED;
	}
	
	/* build domain tree */
	if (!(tree = domaintree_tree(r->pool, DT, host))) {
		return DECLINED;
	}
	
	/* build path */
	if (!(path = domaintree_path(r->pool, DT, tree))) {
		return DECLINED;
	}
	
	/* apply any aliases */
	domaintree_fake(r->pool, DT, &path);
	
	/* done */
	r->canonical_filename = "";
	r->filename = apr_pstrcat(r->pool, DT->prefix, "/", path, "/", DT->suffix, r->uri, NULL);
	struniqchr(r->filename, '/');
	
	DT_LOG_DBG
		"DomainTree: path done = %s", r->filename
	DT_LOG_END
	
	return OK;
}

static void domaintree_hooks(apr_pool_t *pool)
{
	ap_hook_post_config(domaintree_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(domaintree_hook_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
}

/* }}} */
/* {{{ Configuration */

static void *domaintree_create_srv(apr_pool_t *p, server_rec *s)
{
	MOD_DT_CNF *DT;
	
	DT = (MOD_DT_CNF *) apr_palloc(p, sizeof(MOD_DT_CNF));
	
	DT->server = s;
	DT->enabled = 0;
	DT->stripwww = 1;
	DT->maxdepth = 20;
	
	DT->prefix = "/var/www";
	DT->suffix = "public_html";
	
	DT->aliases.hashtable = apr_hash_make(p);
	DT->aliases.recursion = 0;
	
	return DT;
}

static const char *domaintree_enable(cmd_parms *cmd, void *conf, int flag)
{
	MOD_DT_CNF *DT;
	
	DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
	DT->enabled = flag;
	
	return NULL;
}

static const char *domaintree_stripwww(cmd_parms *cmd, void *conf, int flag)
{
	MOD_DT_CNF *DT;
	
	DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
	DT->stripwww = flag;
	
	return NULL;
}

static const char *domaintree_prefix(cmd_parms *cmd, void *conf, const char *prefix)
{
	MOD_DT_CNF *DT;
	
	DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
	DT->prefix = EMPTY(prefix) ? "/" : trim(apr_pstrdup(cmd->pool, prefix), strlen(prefix), '/', 0, 1);
	
	return NULL;
}

static const char *domaintree_suffix(cmd_parms *cmd, void *conf, const char *suffix)
{
	MOD_DT_CNF *DT;
	
	DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
	DT->suffix = EMPTY(suffix) ? "" : trim(apr_pstrdup(cmd->pool, suffix), strlen(suffix), '/', 1, 1);
	
	return NULL;
}

static const char *domaintree_maxdepth(cmd_parms *cmd, void *conf, const char *max_depth)
{
	long depth;
	
	if ((depth = atol(max_depth))) {
		if (depth > 0L) {
			MOD_DT_CNF *DT;
			DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
			DT->maxdepth = (size_t) depth;
		} else {
			return "Maximum DomainTree depth cannot be negative.";
		}
	}
	
	return NULL;
}

static const char *domaintree_aliasrecursion(cmd_parms *cmd, void *conf, const char *alias_recursion)
{
	long recursion;
	
	if ((recursion = atol(alias_recursion))) {
		if (recursion > 0L) {
			MOD_DT_CNF *DT;
			DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
			DT->aliases.recursion = (size_t) recursion;
		} else {
			return "DomainTree alias recursion cannot be negative.";
		}
	}
	
	return NULL;
}

static const char *domaintree_alias(cmd_parms *cmd, void *conf, const char *fake, const char *real)
{
	MOD_DT_CNF *DT;
	char *f = strtr(apr_pstrdup(cmd->pool, fake), '.', '/'), *r = strtr(apr_pstrdup(cmd->pool, real), '.', '/');
	
	DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
	apr_hash_set(DT->aliases.hashtable, trim(f, strlen(f), '/', 1, 1), APR_HASH_KEY_STRING, trim(r, strlen(r), '/', 1, 1));
	
	return NULL;
}


/* }}} */
/* {{{ Commands */

static command_rec domaintree_commands[] = {
	AP_INIT_FLAG(
		"DomainTreeEnabled", domaintree_enable, NULL, RSRC_CONF,
		"Turn the module on or off."
	),

	AP_INIT_FLAG(
		"DomainTreeStripWWW", domaintree_stripwww, NULL, RSRC_CONF,
		"Strip leading www from host. (default On)"
	),

	AP_INIT_TAKE1(
		"DomainTreePrefix", domaintree_prefix, NULL, RSRC_CONF,
		"DomainTree path prefix. (default /var/www) Do not forget the leading slash!"
	),

	AP_INIT_TAKE1(
		"DomainTreeSuffix", domaintree_suffix, NULL, RSRC_CONF,
		"DomainTree path suffix. (default public_html)"
	),

	AP_INIT_TAKE1(
		"DomainTreeMaxdepth", domaintree_maxdepth, NULL, RSRC_CONF,
		"DomainTree max path depth. (default 20)"
	),

	AP_INIT_TAKE1(
		"DomainTreeAliasRecursion", domaintree_aliasrecursion, NULL, RSRC_CONF,
		"Whether (and how often at the maximum) DomainTree should walk recursively "
		"through the aliases list as long as matching aliases are found. (Default: 0 = turned off)"
	),
	
	AP_INIT_TAKE2(
		"DomainTreeAlias", domaintree_alias, NULL, RSRC_CONF,
		"DomainTree aliases; e.g. DomainTreeAlias com/example/tickets com/example/support (dots or slashes equal)"
	),

	{ NULL }
};

/* }}} */
/* {{{ Module Administrativa */

module AP_MODULE_DECLARE_DATA domaintree_module = {
	STANDARD20_MODULE_STUFF,
	NULL,					/* create per-dir */
	NULL,					/* merge  per-dir */
	domaintree_create_srv,	/* create per-server */
	NULL,					/* merge  per-server */
	domaintree_commands,	/* apr_table_t commands */
	domaintree_hooks		/* hooks */
};

/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
