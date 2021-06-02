// SPDX-License-Identifier: LGPL-2.1-or-later

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "strxcpyx.h"
#include "tfilter.h"
#include "string-util.h"
#include "strv.h"

/* TODO: Add options to open a BPF object file, load program into kernel */

static int fw_tfilter_fill_message(Link *link, TFilter *tfilter, sd_netlink_message *req) {
        TFilterFw *tffw;
        int r;

        assert(link);
        assert(tfilter);
        assert(req);

        tffw = TFILTER_TO_FW(tfilter);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "bpf");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        if (tfilter->classid) {
                r = sd_netlink_message_append_u32(req, TCA_FW_CLASSID, tfilter->classid);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not add TCA_FW_CLASSID attribute: %m");
        }

        if (tffw->indev[0]) {
                r = sd_netlink_message_append_string(req, TCA_FW_INDEV, tffw->indev);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not add TCA_FW_INDEV attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

int config_parse_fw_tfilter_string(
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
        _cleanup_(tfilter_free_or_set_invalidp) TFilter *tfilter = NULL;
        Network *network = data;
        TFilterFw *tffw;
        int r;

        r = tfilter_new_static(TFILTER_KIND_FW, network, filename, section_line, &tfilter);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to create traffic control filter, ignoring assignment: %m");
                return 0;
        }

        tffw = TFILTER_TO_FW(tfilter);

        if (isempty(rvalue)) {
                tffw->indev[0] = '\0';
                goto end;
        }

        if (!strnscpy(tffw->indev, sizeof(tffw->indev), rvalue, strlen(rvalue))) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed as interface name was truncated for Indev=, ignoring assignment: %m");
                return 0;
        }

end:
        TAKE_PTR(tfilter);
        return 0;
}


const TFilterVTable fw_tfilter_vtable = {
        .object_size = sizeof(TFilterFw),
        .tca_kind = "fw",
        .fill_message = fw_tfilter_fill_message,
};
