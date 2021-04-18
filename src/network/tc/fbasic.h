// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "conf-parser.h"
#include "tfilter.h"

/* TODO:
 * ematch
 * action
 * police
 */

typedef struct TFilterBasic {
        TFilter meta;
} TFilterBasic;

DEFINE_TFILTER_CAST(BASIC, TFilterBasic);
extern const TFilterVTable basic_tfilter_vtable;
