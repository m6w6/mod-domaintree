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
 * DomainTreeIgnore *.foo.com *.foo.co.uk
 * DomainTreeForbid html.*
 * <Directory "/sites/com/example/users">
 * # e.g. a symlink to /home
 *     DomainTreeSuexec
 * </Directory>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define MODULE	"mod_domaintree"
#define AUTHOR	"<mike@iworks.at>"
#define VERSION "1.5"

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

#ifndef HAVE_UNIX_SUEXEC
#	ifdef SUEXEC_BIN
#		define HAVE_UNIX_SUEXEC
#	endif
#endif
#ifdef HAVE_UNIX_SUEXEC
#	include "unixd.h"
#endif

#define DBG 0

#define MDT_CNF domaintree_conf
#define MDT_PTR (&domaintree_module)

#define GET_MDT_CNF(srv) ((MDT_CNF *) ap_get_module_config((srv)->module_config, MDT_PTR))

#define IF_SET_ELSE(a, b) (a != -1) ? (a) : (b)

#define NUL '\0'
#define EMPTY(str) ((str == NULL) || (*(str) == NUL))
#if DBG
#	define local static
#else
#	define local static APR_INLINE
#endif

#define DT_LOG_ERR APLOG_MARK, APLOG_ERR, APR_SUCCESS, DT->server, "DomainTree: "
#define DT_LOG_WRN APLOG_MARK, APLOG_WARNING, APR_SUCCESS, DT->server, "DomainTree: "
#define DT_LOG_DBG APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, "DomainTree: "

typedef int STATUS;

typedef struct {
	long		recursion;
	apr_table_t	*faketable;
} aliases_t;

typedef struct {
	char		*host;
	char		*path;
	apr_time_t	lacc;
	apr_pool_t	*pool;
} dircache_entry_t;

typedef struct {
	long				clim;
	apr_hash_t			*hmap;
	apr_pool_t			*pool;
	apr_global_mutex_t	*lock;
} dircache_t;

typedef apr_array_header_t *hostlist_t, *pathlist_t;

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
	hostlist_t	ignore;
	hostlist_t	forbid;
#ifdef HAVE_UNIX_SUEXEC
	pathlist_t	suexec;
#endif
} domaintree_conf;

/* }}} */
/* {{{ dircache */

local char *domaintree_cache_get(MDT_CNF *DT, apr_time_t atime, const char *host)
{
	char *path = NULL;
	dircache_entry_t *cache_entry;
	
	apr_global_mutex_lock(DT->dircache.lock);
	
	if ((cache_entry = apr_hash_get(DT->dircache.hmap, host, APR_HASH_KEY_STRING))) {
		cache_entry->lacc = atime;
		path = cache_entry->path;
	}
	
	apr_global_mutex_unlock(DT->dircache.lock);
	
	if (path) {
		ap_log_error(DT_LOG_DBG "cache hit = %s for %s", path, host);
	}
	
	return path;
}

local void domaintree_cache_set(MDT_CNF *DT, apr_time_t atime, const char *host, const char *path)
{
	apr_pool_t *pool;
	dircache_entry_t *cache_entry;
	
	apr_pool_create(&pool, DT->dircache.pool);
	cache_entry = apr_palloc(pool, sizeof(dircache_entry_t));
	
	cache_entry->pool = pool;
	cache_entry->lacc = atime;
	cache_entry->host = apr_pstrdup(pool, host);
	cache_entry->path = apr_pstrdup(pool, path);
	
	apr_global_mutex_lock(DT->dircache.lock);
	
	if (apr_hash_count(DT->dircache.hmap) >= DT->dircache.clim) {
		apr_hash_index_t *idx;
		dircache_entry_t *purge_this = NULL;
	
		ap_log_error(DT_LOG_WRN "reached cache limit (%ld)", DT->dircache.clim);
		
		for (idx = apr_hash_first(DT->dircache.pool, DT->dircache.hmap); idx; idx = apr_hash_next(idx)) {
			dircache_entry_t *current;
		
			apr_hash_this(idx, NULL, NULL, (void *) &current);
			if ((!purge_this) || (purge_this->lacc > current->lacc)) {
				purge_this = current;
			}
		}
	
		if (purge_this) {
			ap_log_error(DT_LOG_DBG "cache del = %s", purge_this->host);
			apr_hash_set(DT->dircache.hmap, purge_this->host, APR_HASH_KEY_STRING, NULL);
			apr_pool_destroy(purge_this->pool);
		}
	}
	apr_hash_set(DT->dircache.hmap, cache_entry->host, APR_HASH_KEY_STRING, cache_entry);
	
	apr_global_mutex_unlock(DT->dircache.lock);
	
	ap_log_error(DT_LOG_DBG "cache set = %s for %s", path, host);
}

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
	
	while (*match && *string)
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
	
	while (ptr[0]) {
		if (ptr[0] == uniq && ptr[1] == uniq) {
			char *pos = &ptr[1];
			
			for (; pos[1] == uniq; ++pos);
			for (; pos[0]; ++pos) {
				pos[0] = pos[1];
			}
		}
		++ptr;
	}
	
	return string;
}

local char *domaintree_host(apr_pool_t *pool, MDT_CNF *DT, const char *host_name)
{
	size_t len;
	char *port, *host;
	
	if (EMPTY(host_name)) {
		ap_log_error(DT_LOG_WRN "no host/server name");
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
	
	ap_log_error(DT_LOG_DBG "host name = %s for %s", host, host_name);
	
	return host;
}

local char *domaintree_path(apr_pool_t *pool, MDT_CNF *DT, const char *host_name)
{
	long depth = 0, maxdepth = IF_SET_ELSE(DT->maxdepth, 20);
	const char *host = host_name;
	char *path = NULL, *host_ptr;
	
	while ((host_ptr = strchr(host, '.'))) {
		
		/* check max depth */
		if (++depth > maxdepth) {
			ap_log_error(DT_LOG_ERR "maxdepth exceeded (%ld)", maxdepth);
			return NULL;
		}
		
		/* append part */
		if (host_ptr - host) {
			
			/* strip WWW */
			if ((DT->stripwww > 0) && (depth == 1) && (!strncmp(host, "www.", sizeof("www")))) {
				ap_log_error(DT_LOG_DBG "strip www");
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
	
	ap_log_error(DT_LOG_DBG "path name = %s for %s", path, host_name);
	
	return path;
}

local void domaintree_fake(apr_pool_t *pool, MDT_CNF *DT, char **path)
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
			ap_log_error(DT_LOG_ERR	"maximum alias recursion level (%ld) exceeded! Check if you have recursive definitions of DomainTreeAlias directives.", DT->aliases.recursion);
			break;
		}
		
		for (i = 0; i < header->nelts; ++i) {
			const char *begin, *end;
			
			ap_log_error(DT_LOG_DBG "fake test = %s on %s", array[i].key, *path);
			if (strmatch(array[i].key, *path, &begin, &end)) {
				ap_log_error(DT_LOG_DBG "fake done = %s (%s <> %s)", *path, array[i].key, array[i].val);
				*path = apr_pstrcat(local_pool, "/", apr_pstrndup(local_pool, *path, begin - *path), "/", array[i].val, "/", end, NULL);
				more = 1;
			}
		}
	} while (more && (DT->aliases.recursion > 0));
	
	*path = apr_pstrdup(pool, struniqchr(*path, '/'));
	
	apr_pool_destroy(local_pool);
}

#define TEST_IS_BOS 1
#define TEST_IS_EOS 2
#define TEST_IS_AOS 3
local int domaintree_test(MDT_CNF *DT, const char *host, int argc, const char **argv, int flags, const char **bos, const char **eos)
{
	if (argc) {
		int i;
		const char *begin, *end, *host_end = host + strlen(host);
		
		for (i = 0; i < argc; ++i) {
			ap_log_error(DT_LOG_DBG "host test = %s <> %s", argv[i], host);
			if (strmatch(argv[i], host, &begin, &end)) {
				if ((flags & TEST_IS_BOS) && begin != host) {
					continue;
				}
				if ((flags & TEST_IS_EOS) && end != host_end) {
					continue;
				}
				if (bos) {
					*bos = begin;
				}
				if (eos) {
					*eos = end;
				}
				ap_log_error(DT_LOG_DBG "test done = %s by %s", host, argv[i]);
				return i+1;
			}
		}
	}
	return 0;
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
	MDT_CNF *DT;
	char *host, *path, *docroot;
	
	if ((!(DT = GET_MDT_CNF(r->server))) || (DT->enabled < 1)) {
		return DECLINED;
	}
	
#if DBG
	ap_log_error(DT_LOG_DBG "processid = %d", (int) getpid());
#endif
	
	/* get a usable host name */
	if (!(host = domaintree_host(r->pool, DT, ap_get_server_name(r)))) {
		return DECLINED;
	}
	
	/* ignore? */
	if (domaintree_test(DT, host, DT->ignore->nelts, (const char **) DT->ignore->elts, TEST_IS_AOS, NULL, NULL)) {
		return DECLINED;
	}
	
	/* forbid? */
	if (domaintree_test(DT, host, DT->forbid->nelts, (const char **) DT->forbid->elts, TEST_IS_AOS, NULL, NULL)) {
		return HTTP_FORBIDDEN;
	}
	
	/* check cache */
	if ((DT->dircache.clim < 1) || (!(path = domaintree_cache_get(DT, r->request_time, host)))) {
		/* build path */
		if (!(path = domaintree_path(r->pool, DT, host))) {
			return DECLINED;
		}
		
		/* apply any aliases */
		if (apr_table_elts(DT->aliases.faketable)->nelts) {
			domaintree_fake(r->pool, DT, &path);
		}
		
		/* add to cache */
		if (DT->dircache.clim > 0) {
			domaintree_cache_set(DT, r->request_time, host, path);
		}
	}
	
	/* compose virtual docroot */
	docroot = struniqchr(apr_pstrcat(r->pool, DT->prefix, "/", path, "/", DT->suffix, "/", NULL), '/');
	
	/* stat docroot */
	if (DT->statroot > 0) {
		apr_finfo_t sb;
		
		switch (apr_stat(&sb, docroot, APR_FINFO_MIN, r->pool)) {
			case APR_SUCCESS:
			case APR_INCOMPLETE:
				ap_log_error(DT_LOG_DBG "stat path = %s (success)", docroot);
				break;
			
			default:
				ap_log_error(DT_LOG_DBG "stat path = %s (failure)", docroot);
				return DECLINED;
		}
	}
	
	/* set virtual docroot */
	apr_table_set(r->subprocess_env, "VIRTUAL_DOCUMENT_ROOT", docroot);
	
#ifdef HAVE_UNIX_SUEXEC
	/* set suexec note */
	{
		const char *username, *separator;
		
		if (domaintree_test(DT, docroot, DT->suexec->nelts, DT->suexec->elts, TEST_IS_BOS, NULL, &username)) {
			if ((separator = strchr(username, '/'))) {
				username = apr_pstrndup(r->pool, username, separator-username);
			} else {
				username = apr_pstrdup(r->pool, username);
			}
			apr_table_setn(r->notes, "mod_domaintree.suexec", username);
		}
	}
#endif
	
	/* done */
	r->canonical_filename = "";
	r->filename = apr_pstrcat(r->pool, docroot, EMPTY(r->uri) ? NULL : ('/' == *r->uri ? r->uri + 1 : r->uri), NULL);
	
	ap_log_error(DT_LOG_DBG "path done = %s", r->filename);
	
	return OK;
}

#ifdef HAVE_UNIX_SUEXEC
static ap_unix_identity_t *domaintree_hook_get_suexec_identity(const request_rec *r)
{
	ap_unix_identity_t *ugid = NULL;
#if APR_HAS_USER
	const char *username;
	
	if ((username = apr_table_get(r->notes, "mod_domaintree.suexec"))) {
		if ((ugid = apr_palloc(r->pool, sizeof(*ugid)))) {
			if (APR_SUCCESS == apr_uid_get(&ugid->uid, &ugid->gid, username, r->pool)) {
				ugid->userdir = 1;
			}
		}
	}
#endif
	return ugid;
}
#endif

static void domaintree_hooks(apr_pool_t *pool)
{
	static const char * const pre[] = {"mod_alias.c", "mod_userdir.c", NULL};
	
	ap_hook_post_config(domaintree_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(domaintree_hook_translate_name, pre, NULL, APR_HOOK_FIRST);
#ifdef HAVE_UNIX_SUEXEC
	ap_hook_get_suexec_identity(domaintree_hook_get_suexec_identity, NULL, NULL, APR_HOOK_FIRST);
#endif
}

/* }}} */
/* {{{ Configuration */

static void *domaintree_create_srv(apr_pool_t *p, server_rec *s)
{
	MDT_CNF *DT= (MDT_CNF *) apr_palloc(p, sizeof(MDT_CNF));
	
	DT->server = s;
	DT->enabled = -1;
	DT->stripwww = -1;
	DT->statroot = -1;
	DT->maxdepth = -1;
	
	DT->prefix = "/var/www";
	DT->suffix = "public_html";
	
	DT->ignore = apr_array_make(p, 0, sizeof(char *));
	DT->forbid = apr_array_make(p, 0, sizeof(char *));
#ifdef HAVE_UNIX_SUEXEC
	DT->suexec = apr_array_make(p, 0, sizeof(char *));
#endif
	
	DT->aliases.recursion = -1;
	DT->aliases.faketable = apr_table_make(p, 0);
	
	DT->dircache.clim = -1;
	DT->dircache.hmap = apr_hash_make(p);
	apr_pool_create(&DT->dircache.pool, p);
	apr_global_mutex_create(&DT->dircache.lock, __FILE__, APR_LOCK_DEFAULT, p);
#if DBG
	fprintf(stderr, "MDT: cfg create %p\n", DT);
#endif
	return DT;
}

static void *domaintree_merge_srv(apr_pool_t *p, void *old_cfg_ptr, void *new_cfg_ptr)
{
	MDT_CNF *old_cfg = (MDT_CNF *) old_cfg_ptr, *new_cfg = (MDT_CNF *) new_cfg_ptr;
	MDT_CNF *DT = (MDT_CNF *) apr_palloc(p, sizeof(MDT_CNF));
	
	DT->server = new_cfg->server;
	DT->enabled = IF_SET_ELSE(new_cfg->enabled, old_cfg->enabled);
	DT->stripwww = IF_SET_ELSE(new_cfg->stripwww, old_cfg->stripwww);
	DT->statroot = IF_SET_ELSE(new_cfg->statroot, old_cfg->statroot);
	DT->maxdepth = IF_SET_ELSE(new_cfg->maxdepth, old_cfg->maxdepth);
	
	DT->prefix = EMPTY(new_cfg->prefix) ? EMPTY(old_cfg->prefix) ? "/var/www" : old_cfg->prefix : new_cfg->prefix;
	DT->suffix = EMPTY(new_cfg->suffix) ? EMPTY(old_cfg->suffix) ? "public_html" : old_cfg->suffix : new_cfg->suffix;
	
	DT->ignore = apr_array_append(p, new_cfg->ignore, old_cfg->ignore);
	DT->forbid = apr_array_append(p, new_cfg->forbid, old_cfg->forbid);
#ifdef HAVE_UNIX_SUEXEC
	DT->suexec = apr_array_append(p, new_cfg->suexec, old_cfg->suexec);
#endif
	
	DT->aliases.recursion = IF_SET_ELSE(new_cfg->aliases.recursion, old_cfg->aliases.recursion);
	DT->aliases.faketable = apr_table_overlay(p, new_cfg->aliases.faketable, old_cfg->aliases.faketable);
	
	DT->dircache.clim = IF_SET_ELSE(new_cfg->dircache.clim, old_cfg->dircache.clim);
	DT->dircache.hmap = apr_hash_overlay(p, new_cfg->dircache.hmap, old_cfg->dircache.hmap);
	apr_global_mutex_create(&new_cfg->dircache.lock, __FILE__, APR_LOCK_DEFAULT, p);
#if DBG
	fprintf(stderr, "MDT: cfg merge  %p + %p = %p\n", old_cfg, new_cfg, DT);
#endif
	return DT;
}

static const char *domaintree_init_enable(cmd_parms *cmd, void *conf, int flag)
{
	GET_MDT_CNF(cmd->server)->enabled = flag;
	return NULL;
}

static const char *domaintree_init_stripwww(cmd_parms *cmd, void *conf, int flag)
{
	GET_MDT_CNF(cmd->server)->stripwww = flag;
	return NULL;
}

static const char *domaintree_init_statroot(cmd_parms *cmd, void *conf, int flag)
{
	GET_MDT_CNF(cmd->server)->statroot = flag;
	return NULL;
}

static const char *domaintree_init_prefix(cmd_parms *cmd, void *conf, const char *prefix)
{
	GET_MDT_CNF(cmd->server)->prefix = EMPTY(prefix) ? "/" : trim(apr_pstrdup(cmd->pool, prefix), strlen(prefix), '/', TRIM_RIGHT);
	return NULL;
}

static const char *domaintree_init_suffix(cmd_parms *cmd, void *conf, const char *suffix)
{
	GET_MDT_CNF(cmd->server)->suffix = EMPTY(suffix) ? "" : trim(apr_pstrdup(cmd->pool, suffix), strlen(suffix), '/', TRIM_BOTH);
	return NULL;
}

static const char *domaintree_init_maxdepth(cmd_parms *cmd, void *conf, const char *max_depth)
{
	long depth;
	
	if ((depth = atol(max_depth))) {
		if (depth >= 0L) {
			GET_MDT_CNF(cmd->server)->maxdepth = depth;
		} else {
			return "Maximum DomainTree depth cannot be negative.";
		}
	}
	
	return NULL;
}

static const char *domaintree_init_aliasrecursion(cmd_parms *cmd, void *conf, const char *alias_recursion)
{
	long recursion;
	
	if ((recursion = atol(alias_recursion))) {
		if (recursion >= 0L) {
			GET_MDT_CNF(cmd->server)->aliases.recursion = recursion;
		} else {
			return "DomainTree alias recursion cannot be negative.";
		}
	}
	
	return NULL;
}

static const char *domaintree_init_alias(cmd_parms *cmd, void *conf, const char *fake, const char *real)
{
	char *f = strtr(apr_pstrdup(cmd->pool, fake), '.', '/'), *r = strtr(apr_pstrdup(cmd->pool, real), '.', '/');
	
	apr_table_set(GET_MDT_CNF(cmd->server)->aliases.faketable, trim(f, strlen(f), '/', TRIM_BOTH), trim(r, strlen(r), '/', TRIM_BOTH));
	
	return NULL;
}

static const char *domaintree_init_cache(cmd_parms *cmd, void *conf, const char *cache)
{
	long limit;
	
	if ((limit = atol(cache))) {
		if (limit >= 0L) {
			GET_MDT_CNF(cmd->server)->dircache.clim = limit;
		} else {
			return "DomainTree cache limit cannot be negative.";
		}
	}
	
	return NULL;
}

static const char *domaintree_init_ignore(cmd_parms *cmd, void *conf, const char *ignore)
{
	*((char **) apr_array_push(GET_MDT_CNF(cmd->server)->ignore)) = trim(apr_pstrdup(cmd->pool, ignore), strlen(ignore), '.', TRIM_BOTH);
	return NULL;
}

static const char *domaintree_init_forbid(cmd_parms *cmd, void *conf, const char *forbid)
{
	*((char **) apr_array_push(GET_MDT_CNF(cmd->server)->forbid)) = trim(apr_pstrdup(cmd->pool, forbid), strlen(forbid), '.', TRIM_BOTH);
	return NULL;
}

static const char *domaintree_init_suexec(cmd_parms *cmd, void *conf)
{
#ifdef HAVE_UNIX_SUEXEC
	apr_finfo_t sb;
	
	if (!cmd->path) {
		return "DomainTreeSuexec is a per directory configuration directive";
	}
	
	switch (apr_stat(&sb, cmd->path, APR_FINFO_MIN, cmd->pool)) {
		case APR_SUCCESS:
		case APR_INCOMPLETE:
			break;
		default:
			return "DomainTreeSuexec must be defined for an existing path";
	}
	
	*((char **) apr_array_push(GET_MDT_CNF(cmd->server)->suexec)) = trim(apr_pstrdup(cmd->pool, cmd->path), strlen(cmd->path), '.', TRIM_BOTH);
	
	return NULL;
#else
	return "HAVE_UNIX_SUEXEC was undefined at compile time";
#endif
}

/* }}} */
/* {{{ Commands */

static command_rec domaintree_commands[] = {
	AP_INIT_FLAG(
		"DomainTreeEnabled", domaintree_init_enable, NULL, RSRC_CONF,
		"Turn the module on or off."
	),

	AP_INIT_FLAG(
		"DomainTreeStripWWW", domaintree_init_stripwww, NULL, RSRC_CONF,
		"Strip leading www from host. (default On)"
	),

	AP_INIT_FLAG(
		"DomainTreeStatRoot", domaintree_init_statroot, NULL, RSRC_CONF,
		"Wheter to check for the evaluated virtual document root with a stat call. (default Off)"
	),

	AP_INIT_TAKE1(
		"DomainTreePrefix", domaintree_init_prefix, NULL, RSRC_CONF,
		"DomainTree path prefix. (default /var/www) Do not forget the leading slash!"
	),

	AP_INIT_TAKE1(
		"DomainTreeSuffix", domaintree_init_suffix, NULL, RSRC_CONF,
		"DomainTree path suffix. (default public_html)"
	),

	AP_INIT_TAKE1(
		"DomainTreeMaxdepth", domaintree_init_maxdepth, NULL, RSRC_CONF,
		"DomainTree max path depth. (default 20)"
	),

	AP_INIT_TAKE1(
		"DomainTreeAliasRecursion", domaintree_init_aliasrecursion, NULL, RSRC_CONF,
		"Whether (and how often at the maximum) DomainTree should walk recursively "
		"through the aliases list as long as matching aliases are found. (default: 0 = turned off)"
	),
	
	AP_INIT_TAKE2(
		"DomainTreeAlias", domaintree_init_alias, NULL, RSRC_CONF,
		"DomainTree aliases; e.g. DomainTreeAlias com/example/tickets com/example/support (dots or slashes equal)"
	),
	
	AP_INIT_TAKE1(
		"DomainTreeCache", domaintree_init_cache, NULL, RSRC_CONF,
		"DomainTree server-wide host to directory cache; specify how many cache entries to allow (default: 0 = turned off)"
	),
	
	AP_INIT_ITERATE(
		"DomainTreeIgnore", domaintree_init_ignore, NULL, RSRC_CONF,
		"DomainTree ignored hosts; uses the same matching alogrithm like DomainTreeAlias"
	),
	
	AP_INIT_ITERATE(
		"DomainTreeForbid", domaintree_init_forbid, NULL, RSRC_CONF,
		"DomanTree forbidden hosts; uses the same matching algorithm like DomainTreeAlias"
	),
	
	AP_INIT_NO_ARGS(
		"DomainTreeSuexec", domaintree_init_suexec, NULL, ACCESS_CONF,
		"DomainTree user home directory; enable suexec hook for domain based user-dir hosting in this directory"
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
	domaintree_merge_srv,	/* merge  per-server */
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
