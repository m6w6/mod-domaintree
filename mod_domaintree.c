/*
 * mod_domaintree.c - Apache2
 *
 * $Id$
 *
 * Copyright 2005 Michael Wallner <mike@iworks.at>
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
 * DomainTreeCache 5
 * DomainTreeAliasRecursion Off
 * DomainTreeAlias /??/exmaple /com/exmaple
 * DomainTreeAlias /???/example /com/example
 * DomainTreeAlias /*one/ /anyone/
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
#define VERSION "1.3"

/* {{{ Includes */

#include "apr.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_tables.h"
#include "apr_strings.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#define APR_WANT_MEMFUNC
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

/* }}} */
/* {{{ domaintree_module */

module AP_MODULE_DECLARE_DATA domaintree_module;

/* }}} */
/* {{{ Macros & Types */

#define MOD_DT_CNF domaintree_conf
#define MOD_DT_PTR (&domaintree_module)

#define GET_MOD_DT_CNF(srv) ((MOD_DT_CNF *) ap_get_module_config((srv)->module_config, MOD_DT_PTR))

#define NUL '\0'
#define EMPTY(str) ((str == NULL) || (*(str) == NUL))
#define local static APR_INLINE

#define DT_LOG_ERR ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, DT->server, 
#define DT_LOG_WRN ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, DT->server, 
#define DT_LOG_DBG ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, 
#define DT_LOG_END );

typedef int STATUS;

typedef struct {
	long		recursion;
	apr_table_t	*faketable;
} aliases_t;

struct dircache_entry {
	char		*host;
	char		*path;
	apr_time_t	lacc;
	apr_pool_t	*pool;
};

typedef struct {
	long				clim;
	apr_hash_t			*hmap;
	apr_pool_t			*pool;
	apr_global_mutex_t	*lock;
} dircache_t;

typedef struct {
	server_rec	*server;
	int			enabled;
	int			stripwww;
	int			statroot;
	long		maxdepth;
	char		*prefix;
	char		*suffix;
	aliases_t	aliases;
	dircache_t	dircache;
} domaintree_conf;

/* }}} */
/* {{{ Helpers */

local char *strtr(char *string, char from, char to)
{
	char *ptr = string;
	
	if (from != to) {
		while ((ptr = strchr(ptr, from))) {
			*ptr = to;
		}
	}
	return string;
}

#define TRIM_LEFT 1
#define TRIM_RIGHT 2
#define TRIM_BOTH (TRIM_LEFT|TRIM_RIGHT)
local char *trim(char *string, size_t length, char what, int where)
{
	if (where & TRIM_RIGHT) {
		while (length-- && (string[length] == what)) {
			string[length] = NUL;
		}
	}
	if (where & TRIM_LEFT) {
		while (*string == what) {
			++string;
		}
	}
	return string;
}

local int strmatch(const char *match, const char *string, const char **begin, const char **end)
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

local char *struniqchr(char *string, char uniq)
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

local char *domaintree_host(apr_pool_t *pool, MOD_DT_CNF *DT, const char *host_name)
{
	size_t len;
	char *port, *host;
	
	if (EMPTY(host_name)) {
		DT_LOG_WRN
			"DomainTree: no host/server name"
		DT_LOG_END
		return NULL;
	}
	
	/* copy hostname */
	host = apr_pstrdup(pool, host_name);
	
	/* check for :NN port */
	if ((port = strchr(host, ':'))) {
		len = port - host;
		*port = NUL;
	} else {
		len = strlen(host);
	}
		
	/* strip leading & trailing dots */
	host = trim(host, len, '.', TRIM_BOTH);
	
	DT_LOG_DBG
		"DomainTree: host name = %s for %s", host, host_name
	DT_LOG_END
	
	return host;
}

local char *domaintree_path(apr_pool_t *pool, MOD_DT_CNF *DT, const char *host_name)
{
	long depth = 0;
	const char *host = host_name;
	char *path = NULL, *host_ptr;
	
	while ((host_ptr = strchr(host, '.'))) {
		
		/* check max depth */
		if (++depth > DT->maxdepth) {
			DT_LOG_ERR
				"DomainTree: maxdepth exceeded (%ld)", DT->maxdepth
			DT_LOG_END
			return NULL;
		}
		
		/* append part */
		if (host_ptr - host) {
			
			/* strip WWW */
			if (DT->stripwww && (depth == 1) && (!strncmp(host, "www.", sizeof("www")))) {
				DT_LOG_DBG
					"DomainTree: strip www"
				DT_LOG_END
			} else {
				path = apr_pstrcat(pool, apr_pstrndup(pool, host, host_ptr - host), "/", path, NULL);
			}
		}
		
		host = host_ptr + 1;
	}
	
	/* append last part if any and duplicate full path */
	if (*host) {
		path = apr_pstrcat(pool, host, "/", path, NULL);
	}
	
	DT_LOG_DBG
		"DomainTree: path name = %s for %s", path, host_name
	DT_LOG_END
	
	return path;
}

local void domaintree_fake(apr_pool_t *pool, MOD_DT_CNF *DT, char **path)
{
	int i, more;
	long recurlevel = 0;
	apr_pool_t *local_pool;
	const apr_array_header_t *header = apr_table_elts(DT->aliases.faketable);
	apr_table_entry_t *array = (apr_table_entry_t *) header->elts;
	
	if (APR_SUCCESS != apr_pool_create(&local_pool, pool)) {
		return;
	}
	
	do {
		more = 0;
		
		if (recurlevel++ > DT->aliases.recursion) {
			DT_LOG_ERR
				"DomainTree: maximum alias recursion level (%ld) exceeded! "
				"Check if you have recursive definitions of DomainTreeAlias directives.", 
				DT->aliases.recursion
			DT_LOG_END
			break;
		}
		
		for (i = 0; i < header->nelts; ++i) {
			const char *begin, *end;
			
			DT_LOG_DBG
				"DomainTree: fake test = %s on %s", array[i].key, *path
			DT_LOG_END
			
			if (strmatch(array[i].key, *path, &begin, &end)) {
				more = 1;
				*path = apr_pstrcat(local_pool, "/", apr_pstrndup(local_pool, *path, begin - *path), "/", array[i].val, "/", end, NULL);
				
				DT_LOG_DBG
					"DomainTree: fake done = %s (%s <> %s)", *path, array[i].key, array[i].val
				DT_LOG_END
			}
		}
	} while (more && DT->aliases.recursion);
	
	*path = apr_pstrdup(pool, struniqchr(*path, '/'));
	
	apr_pool_destroy(local_pool);
}

local char *domaintree_cache_get(MOD_DT_CNF *DT, apr_time_t atime, const char *host)
{
	char *path = NULL;
	struct dircache_entry *cache_entry;
	
	apr_global_mutex_lock(DT->dircache.lock);
	
	if ((cache_entry = apr_hash_get(DT->dircache.hmap, host, APR_HASH_KEY_STRING))) {
		cache_entry->lacc = atime;
		path = cache_entry->path;
	}
	
	apr_global_mutex_unlock(DT->dircache.lock);
	
	if (path) {
		DT_LOG_DBG
			"DomainTree: cache hit = %s for %s", path, host
		DT_LOG_END
	}
	
	return path;
}

local void domaintree_cache_set(MOD_DT_CNF *DT, apr_time_t atime, const char *host, const char *path)
{
	apr_pool_t *pool;
	struct dircache_entry *cache_entry;
	
	apr_pool_create(&pool, DT->dircache.pool);
	cache_entry = apr_palloc(pool, sizeof(struct dircache_entry));
	
	cache_entry->pool = pool;
	cache_entry->lacc = atime;
	cache_entry->host = apr_pstrdup(pool, host);
	cache_entry->path = apr_pstrdup(pool, path);
	
	apr_global_mutex_lock(DT->dircache.lock);
	
	if (apr_hash_count(DT->dircache.hmap) >= DT->dircache.clim) {
		apr_hash_index_t *idx;
		struct dircache_entry *purge_this = NULL;
	
		DT_LOG_WRN
				"DomainTree: reached cache limit (%ld)", DT->dircache.clim
		DT_LOG_END
		
		for (idx = apr_hash_first(DT->dircache.pool, DT->dircache.hmap); idx; idx = apr_hash_next(idx)) {
			struct dircache_entry *current;
		
			apr_hash_this(idx, NULL, NULL, (void **) &current);
			if ((!purge_this) || (purge_this->lacc > current->lacc)) {
				purge_this = current;
			}
		}
	
		if (purge_this) {
			DT_LOG_DBG
					"DomainTree: cache del = %s", purge_this->host
			DT_LOG_END
			apr_hash_set(DT->dircache.hmap, purge_this->host, APR_HASH_KEY_STRING, NULL);
			apr_pool_destroy(purge_this->pool);
		}
	}
	apr_hash_set(DT->dircache.hmap, cache_entry->host, APR_HASH_KEY_STRING, cache_entry);
	
	apr_global_mutex_unlock(DT->dircache.lock);
	
	DT_LOG_DBG
		"DomainTree: cache set = %s for %s", path, host
	DT_LOG_END
}

/* }}} */
/* {{{ Hooks */

static STATUS domaintree_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	ap_add_version_component(pconf, "MDT/" VERSION);
	return OK;
}

static STATUS domaintree_hook_translate_name(request_rec *r)
{
	MOD_DT_CNF *DT = NULL;
	char *host, *path, *docroot;
	
	if ((!(DT = GET_MOD_DT_CNF(r->server))) || (!DT->enabled)) {
		return DECLINED;
	}
	
	DT_LOG_DBG
		"DomainTree: processid = %d", (int) getpid()
	DT_LOG_END
	
	/* get a usable host name */
	if (!(host = domaintree_host(r->pool, DT, ap_get_server_name(r)))) {
		return DECLINED;
	}
	
	/* check cache */
	if ((!DT->dircache.clim) || (!(path = domaintree_cache_get(DT, r->request_time, host)))) {
		/* build path */
		if (!(path = domaintree_path(r->pool, DT, host))) {
			return DECLINED;
		}
		
		/* apply any aliases */
		if (apr_table_elts(DT->aliases.faketable)->nelts) {
			domaintree_fake(r->pool, DT, &path);
		}
		
		/* add to cache */
		if (DT->dircache.clim) {
			domaintree_cache_set(DT, r->request_time, host, path);
		}
	}
	
	/* compose virtual docroot */
	docroot = struniqchr(apr_pstrcat(r->pool, DT->prefix, "/", path, "/", DT->suffix, "/", NULL), '/');
	
	/* stat docroot */
	if (DT->statroot) {
		apr_finfo_t sb;
		
		switch (apr_stat(&sb, docroot, APR_FINFO_MIN, r->pool))
		{
			case APR_SUCCESS:
			case APR_INCOMPLETE:
				DT_LOG_DBG
					"DomainTree: stat path = %s (success)", docroot
				DT_LOG_END
			break;
			
			default:
				DT_LOG_DBG
					"DomainTree: stat path = %s (failure)", docroot
				DT_LOG_END
				return DECLINED;
			break;
		}
	}
	
	/* set virtual docroot */
	apr_table_set(r->subprocess_env, "VIRTUAL_DOCUMENT_ROOT", docroot);
	
	/* done */
	r->canonical_filename = "";
	r->filename = apr_pstrcat(r->pool, docroot, EMPTY(r->uri) ? NULL : ('/' == *r->uri ? r->uri + 1 : r->uri), NULL);
	
	DT_LOG_DBG
		"DomainTree: path done = %s", r->filename
	DT_LOG_END
	
	return OK;
}

static void domaintree_hooks(apr_pool_t *pool)
{
	static const char * const pre[] = {"mod_alias.c", "mod_userdir.c", NULL};
	
	ap_hook_post_config(domaintree_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(domaintree_hook_translate_name, pre, NULL, APR_HOOK_FIRST);
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
	DT->statroot = 0;
	DT->maxdepth = 20;
	
	DT->prefix = "/var/www";
	DT->suffix = "public_html";
	
	DT->aliases.recursion = 0;
	DT->aliases.faketable = apr_table_make(p, 0);
	
	DT->dircache.clim = 0;
	DT->dircache.hmap = apr_hash_make(p);
	apr_pool_create(&DT->dircache.pool, p);
	apr_global_mutex_create(&DT->dircache.lock, __FILE__, APR_LOCK_DEFAULT, p);
	
	return DT;
}

static const char *domaintree_enable(cmd_parms *cmd, void *conf, int flag)
{
	GET_MOD_DT_CNF(cmd->server)->enabled = flag;
	return NULL;
}

static const char *domaintree_stripwww(cmd_parms *cmd, void *conf, int flag)
{
	GET_MOD_DT_CNF(cmd->server)->stripwww = flag;
	return NULL;
}

static const char *domaintree_statroot(cmd_parms *cmd, void *conf, int flag)
{
	GET_MOD_DT_CNF(cmd->server)->statroot = flag;
	return NULL;
}

static const char *domaintree_prefix(cmd_parms *cmd, void *conf, const char *prefix)
{
	GET_MOD_DT_CNF(cmd->server)->prefix = EMPTY(prefix) ? "/" : trim(apr_pstrdup(cmd->pool, prefix), strlen(prefix), '/', TRIM_RIGHT);
	return NULL;
}

static const char *domaintree_suffix(cmd_parms *cmd, void *conf, const char *suffix)
{
	GET_MOD_DT_CNF(cmd->server)->suffix = EMPTY(suffix) ? "" : trim(apr_pstrdup(cmd->pool, suffix), strlen(suffix), '/', TRIM_BOTH);
	return NULL;
}

static const char *domaintree_maxdepth(cmd_parms *cmd, void *conf, const char *max_depth)
{
	long depth;
	
	if ((depth = atol(max_depth))) {
		if (depth > 0L) {
			GET_MOD_DT_CNF(cmd->server)->maxdepth = depth;
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
			GET_MOD_DT_CNF(cmd->server)->aliases.recursion = recursion;
		} else {
			return "DomainTree alias recursion cannot be negative.";
		}
	}
	
	return NULL;
}

static const char *domaintree_alias(cmd_parms *cmd, void *conf, const char *fake, const char *real)
{
	char *f = strtr(apr_pstrdup(cmd->pool, fake), '.', '/'), *r = strtr(apr_pstrdup(cmd->pool, real), '.', '/');
	
	apr_table_set(GET_MOD_DT_CNF(cmd->server)->aliases.faketable, trim(f, strlen(f), '/', TRIM_BOTH), trim(r, strlen(r), '/', TRIM_BOTH));
	
	return NULL;
}

static const char *domaintree_cache(cmd_parms *cmd, void *conf, const char *cache)
{
	long limit;
	
	if ((limit = atol(cache))) {
		if (limit > 0L) {
			GET_MOD_DT_CNF(cmd->server)->dircache.clim = limit;
		} else {
			return "DomainTree cache limit cannot be negative.";
		}
	}
	
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

	AP_INIT_FLAG(
		"DomainTreeStatRoot", domaintree_statroot, NULL, RSRC_CONF,
		"Wheter to check for the evaluated virtual document root with a stat call. (default Off)"
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
		"through the aliases list as long as matching aliases are found. (default: 0 = turned off)"
	),
	
	AP_INIT_TAKE2(
		"DomainTreeAlias", domaintree_alias, NULL, RSRC_CONF,
		"DomainTree aliases; e.g. DomainTreeAlias com/example/tickets com/example/support (dots or slashes equal)"
	),
	
	AP_INIT_TAKE1(
		"DomainTreeCache", domaintree_cache, NULL, RSRC_CONF,
		"DomainTree server-wide host to directory cache; specify how many cache entries to allow (default: 0 = turned off)"
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
	domaintree_commands,	/* config commands */
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
