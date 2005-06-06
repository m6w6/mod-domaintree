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
 *		|	|	+- /organisation
 *		|	|		+- /html
 *		|	+- /example
 *		|		+- /html
 *		+- /com
 *			+- /example
 *				+- /html
 * </pre>
 */

#define MODULE	"mod_domaintree"
#define AUTHOR	"mike@php.net"
#define VERSION "1.0"

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

typedef int STATUS;

typedef struct {
	server_rec	*server;
	int			enabled;
	int			stripwww;
	size_t		maxdepth;
	char		*prefix;
	char		*suffix;
} domaintree_conf;

struct domaintree_entry {
	char *name;
	APR_RING_ENTRY(domaintree_entry) link;
};
APR_RING_HEAD(domaintree, domaintree_entry);

/* }}} */
/* {{{ Helpers */

static APR_INLINE char *domaintree_host(apr_pool_t *pool, MOD_DT_CNF *DT, const char *name)
{
	if (EMPTY(name)) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, DT->server, "DomainTree: no host/server name");
		return NULL;
	} else {
		size_t len;
		char *port, *ptr, *host;

		ptr = host = apr_pstrdup(pool, name);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, "DomainTree: host name = %s", host);

		/* check for :NN port */
		if ((port = strchr(ptr, ':'))) {
			len = port - ptr;
		} else {
			len = strlen(ptr);
		}

		/* strip leading and trailing dots */
		while (ptr[len - 1] == '.') {
			--len;
		}
		while (*ptr == '.') {
			++ptr;
			--len;
		}
		host = ptr;

		/* terminate & lowercase */
		ptr[len] = NUL;
		while (*ptr) {
			apr_tolower(*ptr++);
		}

		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, "DomainTree: sane host = %s", host);
		return host;
	}
}

static APR_INLINE const char *domaintree_append(apr_pool_t *pool, struct domaintree *tree, const char *name, size_t length)
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
			ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, DT->server, "DomainTree: maxdepth exceeded = %s", host);
			return NULL;
		}

		/* append part */
		if (host_ptr - host) {

			/* strip WWW */
			if (DT->stripwww && (depth == 1) && (!strncmp(host, "www.", sizeof("www")))) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, "DomainTree: stripping www.");
			} else {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, "DomainTree: host part (%d) = %s",
					depth - 1, domaintree_append(pool, tree, host, host_ptr - host)
				);
			}
		}

		host = host_ptr + 1;
	}

	/* append last part */
	if (!EMPTY(host)) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, "DomainTree: host part (%d) = %s",
			depth, domaintree_append(pool, tree, host, strlen(host))
		);
	}

	return tree;
}

static APR_INLINE char *domaintree_path(apr_pool_t *pool, MOD_DT_CNF *DT, struct domaintree *tree)
{
	struct domaintree_entry *elem;
	char *path = apr_pstrdup(pool, DT->prefix);
	APR_RING_FOREACH(elem, tree, domaintree_entry, link) {
		path = apr_pstrcat(pool, path, "/", elem->name, NULL);
	}
	return path = apr_pstrcat(pool, path, "/", DT->suffix, NULL);
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

	/* done */
	r->canonical_filename = "";
	r->filename = apr_pstrcat(r->pool, path, r->uri, NULL);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, DT->server, "DomainTree: final path = %s", r->filename);

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
	DT->enabled = 1;
	DT->stripwww = 1;
	DT->maxdepth = 20;

	DT->prefix = "/var/www";
	DT->suffix = "public_html";

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
	DT->prefix = EMPTY(prefix) ? "/" : apr_pstrdup(cmd->pool, prefix);

	return NULL;
}

static const char *domaintree_suffix(cmd_parms *cmd, void *conf, const char *suffix)
{
	MOD_DT_CNF *DT;

	DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
	DT->suffix = EMPTY(suffix) ? "/" : apr_pstrdup(cmd->pool, suffix);

	return NULL;
}

static const char *domaintree_maxdepth(cmd_parms *cmd, void *conf, const char *max_depth)
{
	int depth;

	if ((depth = atoi(max_depth))) {
		if (depth > 0) {
			MOD_DT_CNF *DT;
			DT = ap_get_module_config(cmd->server->module_config, MOD_DT_PTR);
			DT->maxdepth = (size_t) depth;
		} else {
			return "Maximum DomainTree depth cannot be negative.";
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

	AP_INIT_TAKE1(
		"DomainTreePrefix", domaintree_prefix, NULL, RSRC_CONF,
		"DomainTree path prefix. (default /var/www)"
	),

	AP_INIT_TAKE1(
		"DomainTreeSuffix", domaintree_suffix, NULL, RSRC_CONF,
		"DomainTree path suffix. (default public_html)"
	),

	AP_INIT_TAKE1(
		"DomainTreeMaxdepth", domaintree_maxdepth, NULL, RSRC_CONF,
		"DomainTree max path depth. (default 20)"
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
	domaintree_hooks		/* register hooks */
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
