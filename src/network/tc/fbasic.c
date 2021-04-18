// SPDX-License-Identifier: LGPL-2.1-or-later

#include "alloc-util.h"
#include "conf-parser.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "tfilter.h"
#include "string-util.h"
#include "strv.h"

static int basic_tfilter_init(TFilter *tfilter) {
        TFilterBasic *tfbasic;

        assert(tfilter);

        tfbasic = TFILTER_TO_BASIC(tfilter);

        return 0;
}

static int basic_tfilter_fill_message(Link *link, TFilter *tfilter, sd_netlink_message *req) {
        TFilterBasic *tfbasic;
        int r;

        assert(link);
        assert(tfilter);
        assert(req);

        r = sd_netlink_message_open_container_union(req, TCA_OPTIONS, "basic");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open container TCA_OPTIONS: %m");

        /* Options */

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close container TCA_OPTIONS: %m");

        return 0;
}

const TFilterVTable basic_tfilter_vtable = {
        .object_size = sizeof(TFilterBasic),
        .tca_kind = "basic",
        .init = basic_tfilter_init,
        .fill_message = basic_tfilter_fill_message,
};
