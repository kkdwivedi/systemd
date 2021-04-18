// SPDX-License-Identifier: LGPL-2.1-or-later

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "tfilter.h"
#include "string-util.h"
#include "strv.h"

static int cgroup_tfilter_init(TFilter *tfilter) {
        TFilterCGroup *tfcgroup;

        assert(tfilter);

        tfcgroup = TFILTER_TO_CGROUP(tfilter);

        return 0;
}

static int cgroup_tfilter_fill_message(Link *link, TFilter *tfilter, sd_netlink_message *req) {
        TFilterCGroup *tfcgroup;
        int r;

        assert(link);
        assert(tfilter);
        assert(req);

        tfcgroup = TFILTER_TO_CGROUP(tfilter);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "bpf");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}
