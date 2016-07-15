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
 * @brief       Minimum NDN consumer
 *
 * @author      Wentao Shang <wentaoshang@gmail.com>
 *
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "thread.h"
#include "random.h"
#include "xtimer.h"

#include <ndn-riot/app.h>
#include <ndn-riot/ndn.h>
#include <ndn-riot/encoding/name.h>
#include <ndn-riot/encoding/interest.h>
#include <ndn-riot/encoding/data.h>
#include <ndn-riot/msg-type.h>

#define DPRINT(...) printf(__VA_ARGS__)
//#define DPRINT(...) {}

static ndn_app_t* handle = NULL;

// static const uint8_t ecc_key_pri[] = {
//     0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
//     0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
//     0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
//     0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
// };

static const uint8_t ecc_key_pub[] = {
    0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
    0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
    0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
    0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
    0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
    0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};

static uint32_t begin;

static int on_data(ndn_block_t* interest, ndn_block_t* data)
{
    (void)interest;

    uint32_t end = xtimer_now();

    ndn_block_t name;
    int r = ndn_data_get_name(data, &name);
    assert(r == 0);
    DPRINT("client (pid=%" PRIkernel_pid "): data received, name=",
           handle->id);
    ndn_name_print(&name);
    putchar('\n');

    DPRINT("client (pid=%" PRIkernel_pid "): RTT=%"PRIu32"us\n",
           handle->id, end - begin);

    ndn_block_t content;
    r = ndn_data_get_content(data, &content);
    assert(r == 0);

    DPRINT("client (pid=%" PRIkernel_pid "): content length = %d\n",
           handle->id, content.len);

    r = ndn_data_verify_signature(data, ecc_key_pub, sizeof(ecc_key_pub));
    if (r != 0)
        DPRINT("client (pid=%" PRIkernel_pid "): fail to verify signature\n",
               handle->id);
    else
        DPRINT("client (pid=%" PRIkernel_pid "): signature valid\n",
               handle->id);

    return NDN_APP_CONTINUE;  // block forever...
}

static int on_timeout(ndn_block_t* interest)
{
    ndn_block_t name;
    int r = ndn_interest_get_name(interest, &name);
    assert(r == 0);

    DPRINT("client (pid=%" PRIkernel_pid "): interest timeout, name=",
           handle->id);
    ndn_name_print(&name);
    putchar('\n');

    return NDN_APP_CONTINUE;  // block forever...
}

static int send_interest(void)
{
    const char* uri = "/ndn";

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
        DPRINT("client (pid=%" PRIkernel_pid "): cannot create name from uri "
               "\"%s\"\n", handle->id, uri);
        return NDN_APP_ERROR;
    }

    uint32_t rand = random_uint32();
    ndn_shared_block_t* sin = ndn_name_append_uint32(&sn->block, rand);
    ndn_shared_block_release(sn);
    if (sin == NULL) {
        DPRINT("client (pid=%" PRIkernel_pid "): cannot append component to "
               "name \"%s\"\n", handle->id, uri);
        return NDN_APP_ERROR;
    }

    uint32_t lifetime = 1000;  // 1 sec

    DPRINT("client (pid=%" PRIkernel_pid "): express interest, name=",
           handle->id);
    ndn_name_print(&sin->block);
    putchar('\n');

    begin = xtimer_now();
    int r = ndn_app_express_interest(handle, &sin->block, NULL, lifetime,
                                     on_data, on_timeout);
    ndn_shared_block_release(sin);
    if (r != 0) {
        DPRINT("client (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

void ndn_consumer(void)
{
    char c;
    do {
        DPRINT("client (pid=%" PRIkernel_pid "): enter 's' to start\n",
               thread_getpid());
        c = getchar();
    }
    while(c != 's' && c != 'S');

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("client (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return;
    }

    send_interest();

    DPRINT("client (pid=%" PRIkernel_pid "): enter app run loop\n",
           handle->id);

    ndn_app_run(handle);

    DPRINT("client (pid=%" PRIkernel_pid "): returned from app run loop\n",
           handle->id);

    ndn_app_destroy(handle);
}
