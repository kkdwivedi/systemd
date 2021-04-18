// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "conf-parser.h"
#include "tfilter.h"

/* TODO:
 * ematch
 * action
 * police
 */

typedef struct TFilterCGroup {
        TFilter meta;
} TFilterCGroup;

DEFINE_TFILTER_CAST(CGROUP, TFilterCGroup);
extern const TFilterVTable cgroup_tfilter_vtable;
