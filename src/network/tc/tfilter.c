// SPDX-License-Identifier: LGPL-2.1-or-later

#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tc-util.h"
#include "tfilter.h"

const TFilterVTable *const tfilter_vtable[_TFILTER_KIND_MAX] = {
        [TFILTER_KIND_BPF] = &bpf_tfilter_vtable,
        [TFILTER_KIND_FW] = &fw_tfilter_vtable,
};

static int tfilter_new(TFilterKind kind, TFilter **ret) {
        _cleanup_(tfilter_freep) TFilter *tfilter = NULL;
        int r;

        tfilter = malloc0(tfilter_vtable[kind]->object_size);
        if (!tfilter)
                return -ENOMEM;

        tfilter->meta.kind = TC_KIND_FILTER;
        tfilter->protocol = ETH_P_ALL;
        tfilter->kind = kind;

        if (TFILTER_VTABLE(tfilter)->init) {
                r = TFILTER_VTABLE(tfilter)->init(tfilter);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(tfilter);

        return 0;
}

int tfilter_new_static(
        TFilterKind kind, Network *network, const char *filename, unsigned int section_line, TFilter **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(tfilter_freep) TFilter *tfilter = NULL;
        TrafficControl *existing;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        existing = ordered_hashmap_get(network->tc_by_section, n);
        if (existing) {
                TFilter *t;

                if (existing->kind != TC_KIND_FILTER)
                        return -EINVAL;

                t = TC_TO_FILTER(existing);

                if (t->kind != kind)
                        return -EINVAL;

                *ret = t;
                return 0;
        }

        r = tfilter_new(kind, &tfilter);
        if (r < 0)
                return r;

        tfilter->network = network;
        tfilter->section = TAKE_PTR(n);

        r = ordered_hashmap_ensure_put(
                &network->tc_by_section, &network_config_hash_ops, tfilter->section, tfilter);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(tfilter);
        return 0;
}

TFilter *tfilter_free(TFilter *tfilter) {
        if (!tfilter)
                return NULL;

        if (TFILTER_VTABLE(tfilter)->destroy)
                TFILTER_VTABLE(tfilter)->destroy(tfilter);

        if (tfilter->network && tfilter->section)
                ordered_hashmap_remove(tfilter->network->tc_by_section, tfilter->section);

        network_config_section_free(tfilter->section);

        return mfree(tfilter);
}

static int tfilter_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->tc_messages > 0);
        link->tc_messages--;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set TFilter");
                link_enter_failed(link);
                return 1;
        }

        if (link->tc_messages == 0) {
                log_link_debug(link, "Traffic control configured");
                link->tc_configured = true;
                link_check_ready(link);
        }

        return 1;
}

int tfilter_configure(Link *link, TFilter *tfilter) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        struct tc_estimator est;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);

        r = sd_rtnl_message_new_tfilter(link->manager->rtnl, &req, RTM_NEWTFILTER, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not create RTM_NEWTFILTER message: %m");

        r = sd_rtnl_message_set_tfilter_parent(req, tfilter->parent);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set tcm_parent: %m");

        r = sd_rtnl_message_set_tfilter_handle(req, tfilter->handle);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set tcm_handle: %m");

        r = sd_rtnl_message_set_tfilter_priority(req, tfilter->priority);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set tcm_info: %m");

        r = sd_rtnl_message_set_tfilter_protocol(req, tfilter->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set tcm_info: %m");

        r = sd_netlink_message_append_u32(req, TCA_CHAIN, tfilter->chain);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set TCA_CHAIN attribute: %m");

        if (tfilter->kind >= _TFILTER_KIND_MAX)
                return -EINVAL;
        r = sd_netlink_message_append_string(req, TCA_KIND, tfilter_vtable[tfilter->kind]->tca_kind);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set TCA_KIND attribute: %m");

        if (TFILTER_VTABLE(tfilter)->fill_message) {
                r = TFILTER_VTABLE(tfilter)->fill_message(link, tfilter, req);
                if (r < 0)
                        return r;
        }

        if (tfilter->est_interval ^ tfilter->est_time_const)
                return log_link_error_errno(link, -EINVAL, "Both of EstimatorInterval= and EstimatorTimeConst= must be set");

        if (tfilter->est_interval) {
                r = parse_estimator(tfilter->est_interval, tfilter->est_time_const, &est);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to parse estimator: %m");

                r = sd_netlink_message_append_data(req, TCA_RATE, &est, sizeof(est));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set TCA_RATE attribute: %m");
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, tfilter_handler, link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->tc_messages++;

        return 0;
}

int tfilter_section_verify(TFilter *tfilter) {
        int r;

        assert(tfilter);

        if (section_is_invalid(tfilter->section))
                return -EINVAL;

        if (TFILTER_VTABLE(tfilter)->verify) {
                r = TFILTER_VTABLE(tfilter)->verify(tfilter);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_tfilter_parent(
        const char *unit,
        const char *filename,
        unsigned int line,
        const char *section,
        unsigned int section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->parent = TC_H_UNSPEC;
                goto end;
        }

        if (streq(rvalue, "root"))
                tfilter->parent = TC_H_ROOT;
        else if (streq(rvalue, "none"))
                tfilter->parent = TC_H_UNSPEC;
        else if (streq(rvalue, "ingress"))
                tfilter->parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
        else if (streq(rvalue, "egress"))
                tfilter->parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
        else {
                r = parse_handle(rvalue, &tfilter->parent);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse Parent=, ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}

int config_parse_tfilter_handle(
        const char *unit,
        const char *filename,
        unsigned int line,
        const char *section,
        unsigned int section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->handle = TC_H_UNSPEC;
                goto end;
        }

        r = safe_atou32(rvalue, &tfilter->handle);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse Handle=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}

int config_parse_tfilter_chain(
        const char *unit,
        const char *filename,
        unsigned int line,
        const char *section,
        unsigned int section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->chain = 0;
                goto end;
        }

        r = safe_atou32(rvalue, &tfilter->chain);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse Chain=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}

int config_parse_tfilter_priority(
        const char *unit,
        const char *filename,
        unsigned int line,
        const char *section,
        unsigned int section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->priority = 0;
                goto end;
        }

        r = safe_atou16(rvalue, &tfilter->priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse Priority=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}

int config_parse_tfilter_protocol(
        const char *unit,
        const char *filename,
        unsigned int line,
        const char *section,
        unsigned int section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->protocol = ETH_P_ALL;
                goto end;
        }

        r = parse_protocol(rvalue, &tfilter->protocol);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse Protocol=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}

int config_parse_tfilter_classid(
        const char *unit,
        const char *filename,
        unsigned int line,
        const char *section,
        unsigned int section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->classid = TC_H_UNSPEC;
                goto end;
        }

        r = parse_handle(rvalue, &tfilter->classid);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse ClassId=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}

int config_parse_tfilter_est_interval(
        const char *unit,
        const char *filename,
        unsigned int line,
        const char *section,
        unsigned int section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->est_interval = 0;
                goto end;
        }

        r = parse_time(rvalue, &tfilter->est_interval, 0);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse EstimatorInterval=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}

int config_parse_tfilter_est_time_const(
        const char *unit,
        const char *filename,
        unsigned int line,
        const char *section,
        unsigned int section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = tfilter_new_static(ltype, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                tfilter->est_time_const = 0;
                goto end;
        }

        r = parse_time(rvalue, &tfilter->est_time_const, 0);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse EstimatorTimeConst=, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}
