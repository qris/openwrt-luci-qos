/*
 * tc_wrapper.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Chris Wilson <chris+tc_wrapper.c@qwirx.com>
 *
 * Based on tc_class.c from iproute2.
 * Authors:	Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 */

#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "lauxlib.h" 
#include "lualib.h" 

#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"

int filter_ifindex;
__u32 filter_qdisc;
__u32 filter_classid;

int data_table_index, error_table_index;
int num_entries;

static int htb_write_opt(lua_State *lua, struct qdisc_util *qu, struct rtattr *opt)
{
	struct rtattr *tb[TCA_HTB_RTAB+1];
	struct tc_htb_opt *hopt;
	struct tc_htb_glob *gopt;
	double buffer,cbuffer;
	unsigned int linklayer;
	SPRINT_BUF(b1);
	SPRINT_BUF(b4);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_HTB_RTAB, opt);

	if (tb[TCA_HTB_PARMS])
	{
		hopt = RTA_DATA(tb[TCA_HTB_PARMS]);
		if (RTA_PAYLOAD(tb[TCA_HTB_PARMS])  < sizeof(*hopt)) return -1;

		if (!hopt->level)
		{
			lua_pushstring(lua, "prio");
			lua_pushinteger(lua, (int)hopt->prio);
			lua_settable(lua, -3);

			lua_pushstring(lua, "quantum");
			lua_pushinteger(lua, (int)hopt->quantum);
			lua_settable(lua, -3);
		}

		lua_pushstring(lua, "rate");
		lua_pushinteger(lua, hopt->rate.rate);
		lua_settable(lua, -3);

		lua_pushstring(lua, "overhead");
		lua_pushinteger(lua, hopt->rate.overhead);
		lua_settable(lua, -3);

		lua_pushstring(lua, "ceil");
		lua_pushinteger(lua, hopt->ceil.rate);
		lua_settable(lua, -3);

		buffer = tc_calc_xmitsize(hopt->rate.rate, hopt->buffer);
		cbuffer = tc_calc_xmitsize(hopt->ceil.rate, hopt->cbuffer);
		linklayer = (hopt->rate.linklayer & TC_LINKLAYER_MASK);

		if (linklayer > TC_LINKLAYER_ETHERNET)
		{
			lua_pushstring(lua, "linklayer");
			lua_pushstring(lua, sprint_linklayer(linklayer, b4));
			lua_settable(lua, -3);
		}

		lua_pushstring(lua, "burst");
		lua_pushinteger(lua, buffer);
		lua_settable(lua, -3);

		lua_pushstring(lua, "burst_cell_log");
		lua_pushinteger(lua, hopt->rate.cell_log);
		lua_settable(lua, -3);

		lua_pushstring(lua, "mpu");
		lua_pushinteger(lua, hopt->rate.mpu & 0xFF);
		lua_settable(lua, -3);

		lua_pushstring(lua, "burst_overhead");
		lua_pushinteger(lua, (hopt->rate.mpu >> 8) & 0xFF);
		lua_settable(lua, -3);

		lua_pushstring(lua, "cburst");
		lua_pushinteger(lua, cbuffer);
		lua_settable(lua, -3);

		lua_pushstring(lua, "cburst_cell_log");
		lua_pushinteger(lua, hopt->ceil.cell_log);
		lua_settable(lua, -3);

		lua_pushstring(lua, "mpu");
		lua_pushinteger(lua, hopt->ceil.mpu & 0xFF);
		lua_settable(lua, -3);

		lua_pushstring(lua, "burst_overhead");
		lua_pushinteger(lua, (hopt->ceil.mpu >> 8) & 0xFF);
		lua_settable(lua, -3);

		lua_pushstring(lua, "level");
		lua_pushinteger(lua, (int)hopt->level);
		lua_settable(lua, -3);
	}

	if (tb[TCA_HTB_INIT]) {
		gopt = RTA_DATA(tb[TCA_HTB_INIT]);
		if (RTA_PAYLOAD(tb[TCA_HTB_INIT])  < sizeof(*gopt)) return -1;

		lua_pushstring(lua, "r2q");
		lua_pushinteger(lua, gopt->rate2quantum);
		lua_settable(lua, -3);

		lua_pushstring(lua, "default_class");
		lua_pushinteger(lua, gopt->defcls);
		lua_settable(lua, -3);

		lua_pushstring(lua, "direct_pkts");
		lua_pushinteger(lua, gopt->direct_pkts);
		lua_settable(lua, -3);

		lua_pushstring(lua, "version");
		lua_pushinteger(lua, gopt->version);
		lua_settable(lua, -3);
	}

	return 0;
}

int htb_write_xstats(lua_State *lua, struct qdisc_util *qu, struct rtattr *xstats)
{
	struct tc_htb_xstats *st;
	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
	{
		luaL_error(lua, "HTB stats too short: expected %d bytes, "
			"got %d", sizeof(*st), RTA_PAYLOAD(xstats));
		return -1;
	}

	st = RTA_DATA(xstats);

	lua_pushstring(lua, "lended");
	lua_pushnumber(lua, st->lends);
	lua_settable(lua, -3);

	lua_pushstring(lua, "borrowed");
	lua_pushnumber(lua, st->borrows);
	lua_settable(lua, -3);

	lua_pushstring(lua, "giants");
	lua_pushnumber(lua, st->giants);
	lua_settable(lua, -3);

	lua_pushstring(lua, "tokens");
	lua_pushnumber(lua, st->tokens);
	lua_settable(lua, -3);

	lua_pushstring(lua, "ctokens");
	lua_pushnumber(lua, st->ctokens);
	lua_settable(lua, -3);

	return 0;
}

void write_tcstats2_attr(lua_State *lua, struct rtattr *rta, struct rtattr **xstats)
{
	struct rtattr *tbs[TCA_STATS_MAX + 1];

	parse_rtattr_nested(tbs, TCA_STATS_MAX, rta);

	if (tbs[TCA_STATS_BASIC]) {
		struct gnet_stats_basic bs = {0};
		memcpy(&bs, RTA_DATA(tbs[TCA_STATS_BASIC]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_BASIC]), sizeof(bs)));

		lua_pushstring(lua, "bytes");
		lua_pushnumber(lua, bs.bytes);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "packets");
		lua_pushnumber(lua, bs.packets);
		lua_settable(lua, -3);
	}

	if (tbs[TCA_STATS_QUEUE]) {
		struct gnet_stats_queue q = {0};
		memcpy(&q, RTA_DATA(tbs[TCA_STATS_QUEUE]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_QUEUE]), sizeof(q)));

		lua_pushstring(lua, "dropped");
		lua_pushnumber(lua, q.drops);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "overlimits");
		lua_pushnumber(lua, q.overlimits);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "requeues");
		lua_pushnumber(lua, q.requeues);
		lua_settable(lua, -3);
	}

	if (tbs[TCA_STATS_RATE_EST]) {
		struct gnet_stats_rate_est re = {0};
		memcpy(&re, RTA_DATA(tbs[TCA_STATS_RATE_EST]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_RATE_EST]), sizeof(re)));

		lua_pushstring(lua, "bps");
		lua_pushnumber(lua, re.bps);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "pps");
		lua_pushnumber(lua, re.pps);
		lua_settable(lua, -3);
	}

	if (tbs[TCA_STATS_QUEUE]) {
		struct gnet_stats_queue q = {0};
		memcpy(&q, RTA_DATA(tbs[TCA_STATS_QUEUE]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_QUEUE]), sizeof(q)));

		lua_pushstring(lua, "queue_bytes");
		lua_pushnumber(lua, q.backlog);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "queue_packets");
		lua_pushnumber(lua, q.qlen);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "requeues");
		lua_pushnumber(lua, q.requeues);
		lua_settable(lua, -3);
	}

	if (xstats)
		*xstats = tbs[TCA_STATS_APP] ? tbs[TCA_STATS_APP] : NULL;
}

void write_tcstats_attr(lua_State *lua, struct rtattr *tb[],
	struct rtattr **xstats)
{
	if (tb[TCA_STATS2]) {
		write_tcstats2_attr(lua, tb[TCA_STATS2], xstats);
		if (xstats && NULL == *xstats)
			goto compat_xstats;
		return;
	}

	/* backward compatibility */
	if (tb[TCA_STATS]) {
		struct tc_stats st;

		/* handle case where kernel returns more/less than we know about */
		memset(&st, 0, sizeof(st));
		memcpy(&st, RTA_DATA(tb[TCA_STATS]), MIN(RTA_PAYLOAD(tb[TCA_STATS]), sizeof(st)));

		lua_pushstring(lua, "bytes");
		lua_pushnumber(lua, st.bytes);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "packets");
		lua_pushnumber(lua, st.packets);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "drops");
		lua_pushnumber(lua, st.drops);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "overlimits");
		lua_pushnumber(lua, st.overlimits);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "bps");
		lua_pushnumber(lua, st.bps);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "pps");
		lua_pushnumber(lua, st.pps);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "queue_bytes");
		lua_pushnumber(lua, st.backlog);
		lua_settable(lua, -3);
		
		lua_pushstring(lua, "queue_packets");
		lua_pushnumber(lua, st.qlen);
		lua_settable(lua, -3);
	}

compat_xstats:
	if (tb[TCA_XSTATS] && xstats)
		*xstats = tb[TCA_XSTATS];
}

int write_class(const struct sockaddr_nl *who,
       struct nlmsghdr *n, void *arg)
{
	lua_State *lua = (lua_State *) arg;
	struct tcmsg *t = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * tb[TCA_MAX+1];
	struct qdisc_util *q;
	char abuf[256];
	char classid_str_buf[256];

	if (n->nlmsg_type != RTM_NEWTCLASS && n->nlmsg_type != RTM_DELTCLASS) {
		luaL_error(lua, "Not a class");
		return -1;
	}
	len -= NLMSG_LENGTH(sizeof(*t));
	if (len < 0) {
		luaL_error(lua, "Wrong len %d", len);
		return -1;
	}
	if (filter_qdisc && TC_H_MAJ(t->tcm_handle^filter_qdisc))
		return 0;

	if (filter_classid && t->tcm_handle != filter_classid)
		return 0;

	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, TCA_MAX, TCA_RTA(t), len);

	if (tb[TCA_KIND] == NULL) {
		luaL_error(lua, "write_class: NULL kind");
		return -1;
	}

	int all_classes_table_id = lua_gettop(lua);

	lua_newtable(lua);
	int this_class_table_id = lua_gettop(lua);

	#define PUSH_VALUE(key, value) \
		{ \
			lua_pushstring(lua, key); \
			lua_pushstring(lua, value); \
			lua_settable(lua, this_class_table_id); \
		}

	if (n->nlmsg_type == RTM_DELTCLASS)
	{
		lua_pushstring(lua, "deleted");
		lua_pushinteger(lua, 1);
		lua_settable(lua, this_class_table_id);
	
	}

	PUSH_VALUE("type", rta_getattr_str(tb[TCA_KIND]));

	if (!t->tcm_handle)
	{
		PUSH_VALUE("error", "class without a handle");
	}
	else
	{
		if (filter_qdisc)
			print_tc_classid(classid_str_buf,
				sizeof(classid_str_buf),
				TC_H_MIN(t->tcm_handle));
		else
			print_tc_classid(classid_str_buf,
				sizeof(classid_str_buf),
				t->tcm_handle);
	}

	PUSH_VALUE("id", abuf);

	if (filter_ifindex == 0)
		PUSH_VALUE("dev", ll_index_to_name(t->tcm_ifindex));

	if (t->tcm_parent == TC_H_ROOT)
	{
		PUSH_VALUE("parent", NULL);
	}
	else
	{
		if (filter_qdisc)
			print_tc_classid(classid_str_buf,
				sizeof(classid_str_buf),
				TC_H_MIN(t->tcm_parent));
		else
			print_tc_classid(classid_str_buf,
				sizeof(classid_str_buf),
				t->tcm_parent);
		PUSH_VALUE("parent", classid_str_buf);
	}

	if (t->tcm_info)
	{
		lua_pushstring(lua, "leaf");
		lua_pushinteger(lua, t->tcm_info >> 16);
		lua_settable(lua, this_class_table_id);
	}

	q = get_qdisc_kind(RTA_DATA(tb[TCA_KIND]));

	if (!tb[TCA_OPTIONS])
	{
		PUSH_VALUE("error", "no options");
	}
	else if (!q)
	{
		PUSH_VALUE("error", "no queue information");
	}
	else if (strcmp(q->id, "htb") == 0)
	{
		htb_write_opt(lua, q, tb[TCA_OPTIONS]);

		struct rtattr *xstats = NULL;

		if (tb[TCA_STATS] || tb[TCA_STATS2])
		{
			write_tcstats_attr(lua, tb, &xstats);
		}

		if (xstats || tb[TCA_XSTATS])
		{
			htb_write_xstats(lua, q, xstats ? xstats : tb[TCA_XSTATS]);
		}
	}
	else
	{
		PUSH_VALUE("error", "unsupported queue type");
	}

	// Push a new key onto the stack, then move it below the table
	assert(lua_gettop(lua) == this_class_table_id);
	lua_pushinteger(lua, num_entries);
	lua_insert(lua, this_class_table_id);

	// And put the key and value (this table) into the complete list
	lua_settable(lua, all_classes_table_id);
	assert(lua_gettop(lua) == all_classes_table_id);

	return 0;
}

int tc_class_list(lua_State *lua)
{
	const char *device_name = luaL_checkstring(lua, 1);

	struct tcmsg t;
	memset(&t, 0, sizeof(t));
	t.tcm_family = AF_UNSPEC;

	if ((t.tcm_ifindex = ll_name_to_index(device_name)) == 0) {
		luaL_error(lua, "Cannot find device \"%s\"", device_name);
		return 0; // no values
	}

	lua_newtable(lua);
	data_table_index = lua_gettop(lua);

	filter_ifindex = t.tcm_ifindex;
 	ll_init_map(&rth);

 	if (rtnl_dump_request(&rth, RTM_GETTCLASS, &t, sizeof(t)) < 0) {
		luaL_error(lua, "Cannot send dump request");
		return 0; // no values
	}

	num_entries = 0;
 	if (rtnl_dump_filter(&rth, write_class, lua) < 0) {
		luaL_error(lua, "Dump terminated");
		return 0; // no values
	}

	return 1; // just the table on top of the stack
}

static const struct luaL_Reg tc_wrapper [] =
{
	{"tc_class_list", tc_class_list},
	{NULL, NULL}  /* sentinel */
};

int luaopen_qwirx_qos_c(lua_State *L)
{
	// luaL_newlib(L, tc_class_list);
	luaL_register(L, "qwirx_qos_c", tc_wrapper);
	return 1;
}

