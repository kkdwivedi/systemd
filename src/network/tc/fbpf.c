// SPDX-License-Identifier: LGPL-2.1-or-later

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "tfilter.h"
#include "string-util.h"
#include "strv.h"

static int bpf_tfilter_init(TFilter *tfilter) {
        TFilterBPF *tfbpf;

        assert(tfilter);

        tfbpf = TFILTER_TO_BPF(tfilter);

        return 0;
}

static int bpf_tfilter_fill_message(Link *link, TFilter *tfilter, sd_netlink_message *req) {
        TFilterBPF *tfbpf;
        int r;

        assert(link);
        assert(tfilter);
        assert(req);

        tfbpf = TFILTER_TO_BPF(tfilter);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "bpf");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        r = sd_netlink_message_append_u32(req, TCA_BPF_CLASSID, tfilter->classid);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add TCA_BPF_CLASSID attribute: %m");

        r = sd_netlink_message_append_u32(req, TCA_BPF_FLAGS_GEN, tfbpf->gen_flags);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add TCA_BPF_FLAGS_GEN attribute: %m");

        r = sd_netlink_message_append_u32(req, TCA_BPF_FLAGS, tfbpf->flags);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add TCA_BPF_FLAGS attribute: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

enum bpf_flag_type {
        FLAG_DIRECT,
        FLAG_SKIP_SW,
        FLAG_SKIP_HW,
};

static int config_parse_bpf_tfilter_bool(
        const char *unit,
        const char *filename,
        unsigned line,
        const char *section,
        unsigned section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata,
        enum bpf_flag_type type) {
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        TFilterBPF *tfbpf;
        int r;

        r = tfilter_new_static(TFILTER_KIND_BPF, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        tfbpf = TFILTER_TO_BPF(tfilter);

        if (isempty(rvalue)) {
                if (type)
                        tfbpf->gen_flags = 0;
                else
                        tfbpf->flags = 0;
                goto end;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse '%s'=, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        switch (type) {
                case FLAG_DIRECT:
                        if (r)
                                tfbpf->flags = TCA_BPF_FLAG_ACT_DIRECT;
                        break;
                case FLAG_SKIP_SW:
                        if (r)
                                tfbpf->gen_flags |= TCA_CLS_FLAGS_SKIP_SW;
                        break;
                case FLAG_SKIP_HW:
                        if (r)
                                tfbpf->gen_flags |= TCA_CLS_FLAGS_SKIP_HW;
                        break;
                default:
                        return -ERANGE;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}

int config_parse_bpf_tfilter_direct_action(
        const char *unit,
        const char *filename,
        unsigned line,
        const char *section,
        unsigned section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        int r;

        r = config_parse_bpf_tfilter_bool(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata, 0);
        if (r < 0)
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse DirectAction=, ignoring assignment: %s",
                           rvalue);

        return 0;
}

int config_parse_bpf_tfilter_skip_software(
        const char *unit,
        const char *filename,
        unsigned line,
        const char *section,
        unsigned section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        int r;

        r = config_parse_bpf_tfilter_bool(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata, 1);
        if (r < 0)
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse SkipSoftware=, ignoring assignment: %s",
                           rvalue);

        return 0;
}

int config_parse_bpf_tfilter_skip_hardware(
        const char *unit,
        const char *filename,
        unsigned line,
        const char *section,
        unsigned section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        int r;

        r = config_parse_bpf_tfilter_bool(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata, 2);
        if (r < 0)
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse SkipHardware=, ignoring assignment: %s",
                           rvalue);

        return 0;
}
