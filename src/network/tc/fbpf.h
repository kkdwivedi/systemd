// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "conf-parser.h"
#include "tfilter.h"

/* TODO:
 * bpf object
 * action
 * police
 */

typedef struct TFilterBPF {
        TFilter meta;

        uint32_t gen_flags;
        uint32_t flags;
} TFilterBPF;

DEFINE_TFILTER_CAST(BPF, TFilterBPF);
extern const TFilterVTable bpf_tfilter_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_bpf_tfilter_direct_action);
CONFIG_PARSER_PROTOTYPE(config_parse_bpf_tfilter_skip_software);
CONFIG_PARSER_PROTOTYPE(config_parse_bpf_tfilter_skip_hardware);
