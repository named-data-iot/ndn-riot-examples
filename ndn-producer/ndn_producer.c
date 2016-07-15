/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Minimum NDN producer
 *
 * @author      Wentao Shang <wentaoshang@gmail.com>
 *
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "thread.h"
#include "random.h"

#include "ndn-riot/app.h"
#include "ndn-riot/ndn.h"
#include "ndn-riot/encoding/name.h"
#include "ndn-riot/encoding/interest.h"
#include "ndn-riot/encoding/data.h"
#include "ndn-riot/msg-type.h"

//#define DPRINT(...) printf(__VA_ARGS__)
#define DPRINT(...) {}

static ndn_app_t* handle = NULL;

static const uint8_t ecc_key_pri[] = {
    0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
    0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
    0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};

// static const uint8_t ecc_key_pub[] = {
//     0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
//     0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
//     0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
//     0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
//     0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
//     0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
//     0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
//     0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
// };

static int on_interest(ndn_block_t* interest)
{
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("server (pid=%" PRIkernel_pid "): cannot get name from interest"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("server (pid=%" PRIkernel_pid "): interest received, name=",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    ndn_shared_block_t* sdn = ndn_name_append_uint8(&in, 3);
    if (sdn == NULL) {
        DPRINT("server (pid=%" PRIkernel_pid "): cannot append component to "
               "name\n", handle->id);
        return NDN_APP_ERROR;
    }

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    uint8_t buf[20] = {0};
    ndn_block_t content = { buf, sizeof(buf) };

    ndn_shared_block_t* sd =
        ndn_data_create(&sdn->block, &meta, &content,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                        ecc_key_pri, sizeof(ecc_key_pri));
    if (sd == NULL) {
        DPRINT("server (pid=%" PRIkernel_pid "): cannot create data block\n",
               handle->id);
        ndn_shared_block_release(sdn);
        return NDN_APP_ERROR;
    }

    DPRINT("server (pid=%" PRIkernel_pid "): send data to NDN thread, name=",
           handle->id);
    ndn_name_print(&sdn->block);
    putchar('\n');
    ndn_shared_block_release(sdn);

    // pass ownership of "sd" to the API
    if (ndn_app_put_data(handle, sd) != 0) {
        DPRINT("server (pid=%" PRIkernel_pid "): cannot put data\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("server (pid=%" PRIkernel_pid "): return to the app\n", handle->id);
    return NDN_APP_CONTINUE;
}

void ndn_producer(void)
{
    DPRINT("server (pid=%" PRIkernel_pid "): start\n", thread_getpid());

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("server (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return;
    }

    const char* prefix = "/ndn";
    ndn_shared_block_t* sp = ndn_name_from_uri(prefix, strlen(prefix));
    if (sp == NULL) {
        DPRINT("server (pid=%" PRIkernel_pid "): cannot create name from uri "
               "\"%s\"\n", handle->id, prefix);
        return;
    }

    DPRINT("server (pid=%" PRIkernel_pid "): register prefix \"%s\"\n",
           handle->id, prefix);
    // pass ownership of "sp" to the API
    if (ndn_app_register_prefix(handle, sp, on_interest) != 0) {
        DPRINT("server (pid=%" PRIkernel_pid "): failed to register prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return;
    }

    DPRINT("server (pid=%" PRIkernel_pid "): enter app run loop\n",
           handle->id);

    ndn_app_run(handle);

    DPRINT("server (pid=%" PRIkernel_pid "): returned from app run loop\n",
           handle->id);

    ndn_app_destroy(handle);
}
