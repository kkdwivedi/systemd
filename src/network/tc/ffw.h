// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "conf-parser.h"
#include "tfilter.h"
#include <linux/if.h>

/* TODO:
 * ematch
 * action
 * police
 */

typedef struct TFilterFw {
        TFilter meta;

        char indev[IFNAMSIZ];
} TFilterFw;

DEFINE_TFILTER_CAST(FW, TFilterFw);
extern const TFilterVTable fw_tfilter_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_fw_tfilter_string);
