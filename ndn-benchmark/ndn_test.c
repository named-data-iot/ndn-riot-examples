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
 * @brief       NDN encoding benchmark
 *
 * @author      Wentao Shang <wentaoshang@gmail.com>
 *
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "ndn-riot/encoding/name.h"
#include "ndn-riot/encoding/interest.h"
#include "ndn-riot/encoding/data.h"
#include "random.h"
#include "xtimer.h"

static const unsigned char key[] = { 'd', 'u', 'm', 'm', 'y', 'k', 'e', 'y' };

static const uint8_t ecc_key_pri[] = {
    0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
    0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
    0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};

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

static void test_name_from_uri(void)
{
    uint32_t begin, end;
    const char* uri = "/aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd"
	"/eeeeeeeeee/ffffffffff/gggggggggg/hhhhhhhhhh/iiiiiiiiii/jjjjjjjjjj";

    int repeat = 1000;
    printf("name_from_uri start (repeat=%d)\n", repeat);

    ndn_shared_block_t* sn;
    bool err = false;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	sn = ndn_name_from_uri(uri, strlen(uri));
	if (sn == NULL) {
	    err = true;
	    break;
	}
	ndn_shared_block_release(sn);
    }
    end = xtimer_now();

    if (!err)
	printf("name_from_uri finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("name_from_uri failed\n");
}

static void test_name_get_size(void)
{
    uint32_t begin, end;
    const char* uri = "/aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd"
	"/eeeeeeeeee/ffffffffff/gggggggggg/hhhhhhhhhh/iiiiiiiiii/jjjjjjjjjj";

    int repeat = 100000;
    printf("name_get_size start (repeat=%d)\n", repeat);

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));;
    if (sn == NULL) {
	printf("failed\n");
	return;
    }

    int r;
    bool err = false;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	r = ndn_name_get_size_from_block(&sn->block);
	if (r != 10) {
	    err = true;
	    break;
	}
    }
    end = xtimer_now();

    ndn_shared_block_release(sn);

    if (!err)
	printf("name_get_size finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("name_get_size failed\n");
}

static void test_name_get_component(void)
{
    uint32_t begin, end;
    const char* uri = "/aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd"
	"/eeeeeeeeee/ffffffffff/gggggggggg/hhhhhhhhhh/iiiiiiiiii/jjjjjjjjjj";

    int repeat = 100000;
    printf("name_get_component start (repeat=%d)\n", repeat);

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));;
    if (sn == NULL) {
	printf("failed\n");
	return;
    }

    int r;
    ndn_name_component_t comp;
    bool err = false;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	r = ndn_name_get_component_from_block(&sn->block, 4, &comp);
	if (r != 0 && comp.buf[0] != 'e' && comp.len != 10) {
	    err = true;
	    break;
	}
    }
    end = xtimer_now();

    ndn_shared_block_release(sn);

    if (!err)
	printf("name_get_component finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("name_get_component failed\n");
}

static void test_name_append(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[20] = {1};

    int repeat = 1000;
    printf("name_append start (repeat=%d)\n", repeat);

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("failed\n");
	return;
    }

    bool err = false;
    ndn_shared_block_t *sin;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	sin = ndn_name_append(&sn->block, buf, sizeof(buf));
	if (sin == NULL) {
	    err = true;
	    break;
	}
	ndn_shared_block_release(sin);
    }
    end = xtimer_now();

    if (!err)
	printf("name_append finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("name_append failed\n");

    ndn_shared_block_release(sn);
}

static void test_data_create_digest(void)
{
    int repeat = 1000;
    printf("data_create digest start (repeat=%d)\n", repeat);

    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    ndn_shared_block_t *sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("data_create digest failed\n");
	return;
    }

    bool err = false;
    ndn_shared_block_t *sd;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

	ndn_block_t content = { buf, sizeof(buf) };

	sd = ndn_data_create(&sn->block, &meta, &content,
			     NDN_SIG_TYPE_DIGEST_SHA256, NULL,
			     NULL, 0);

	if (sd == NULL) {
	    err = true;
	    break;
	}

	ndn_shared_block_release(sd);
    }
    end = xtimer_now();

    ndn_shared_block_release(sn);

    if (!err)
	printf("data_create digest finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("data_create digest failed\n");
}

static void test_data_create_hmac(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    int repeat = 1000;
    printf("data_create HMAC start (repeat=%d)\n", repeat);

    ndn_shared_block_t *sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("data_create HMAC failed\n");
	return;
    }

    bool err = false;
    ndn_shared_block_t *sd;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

	ndn_block_t content = { buf, sizeof(buf) };

	sd = ndn_data_create(&sn->block, &meta, &content,
			     NDN_SIG_TYPE_HMAC_SHA256, NULL,
			     key, sizeof(key));

	if (sd == NULL) {
	    err = true;
	    break;
	}

	ndn_shared_block_release(sd);
    }
    end = xtimer_now();

    ndn_shared_block_release(sn);

    if (!err)
	printf("data_create HMAC finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("data_create HMAC failed\n");
}

static void test_data_create_ecdsa(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    int repeat = 100;
    printf("data_create ECDSA start (repeat=%d)\n", repeat);

    ndn_shared_block_t *sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("data_create ECDSA failed\n");
	return;
    }

    bool err = false;
    ndn_shared_block_t *sd;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

	ndn_block_t content = { buf, sizeof(buf) };

	sd = ndn_data_create(&sn->block, &meta, &content,
			     NDN_SIG_TYPE_ECDSA_SHA256, NULL,
			     ecc_key_pri, sizeof(ecc_key_pri));

	if (sd == NULL) {
	    err = true;
	    break;
	}

	ndn_shared_block_release(sd);
    }
    end = xtimer_now();

    ndn_shared_block_release(sn);

    if (!err)
	printf("data_create ECDSA finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("data_create ECDSA failed\n");
}

static void test_data_verify_ecdsa(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    int repeat = 100;
    printf("data_verify ECDSA start (repeat=%d)\n", repeat);

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("data_verify ECDSA failed\n");
	return;
    }

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    ndn_block_t content = { buf, sizeof(buf) };

    ndn_shared_block_t* sd =
	ndn_data_create(&sn->block, &meta, &content,
			NDN_SIG_TYPE_ECDSA_SHA256, NULL,
			ecc_key_pri, sizeof(ecc_key_pri));
    if (sd == NULL) {
	printf("data_verify ECDSA failed\n");
	return;
    }
    ndn_shared_block_release(sn);

    int r;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	r = ndn_data_verify_signature(&sd->block, ecc_key_pub,
				      sizeof(ecc_key_pub));
	if (r != 0) {
	    break;
	}
    }
    end = xtimer_now();

    if (r == 0)
	printf("data_verify ECDSA finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("data_verify ECDSA failed\n");

    ndn_shared_block_release(sd);
}

static void test_data_get_name(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    int repeat = 1000000;
    printf("data_get_name start (repeat=%d)\n", repeat);

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("failed\n");
	return;
    }

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    ndn_block_t content = { buf, sizeof(buf) };

    ndn_shared_block_t* sd =
	ndn_data_create(&sn->block, &meta, &content,
			NDN_SIG_TYPE_ECDSA_SHA256, NULL,
			ecc_key_pri, sizeof(ecc_key_pri));
    ndn_shared_block_release(sn);
    if (sd == NULL) {
	printf("failed\n");
	return;
    }

    int r;
    ndn_block_t name;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	r = ndn_data_get_name(&sd->block, &name);
	if (r != 0) {
	    break;
	}
    }
    end = xtimer_now();

    if (r == 0)
	printf("data_get_name finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("data_get_name failed\n");

    ndn_shared_block_release(sd);
}

static void test_data_get_content(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    int repeat = 1000000;
    printf("data_get_content start (repeat=%d)\n", repeat);

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("failed\n");
	return;
    }

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    ndn_block_t content = { buf, sizeof(buf) };

    ndn_shared_block_t* sd =
	ndn_data_create(&sn->block, &meta, &content,
			NDN_SIG_TYPE_ECDSA_SHA256, NULL,
			ecc_key_pri, sizeof(ecc_key_pri));
    ndn_shared_block_release(sn);
    if (sd == NULL) {
	printf("failed\n");
	return;
    }

    int r;
    begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	r = ndn_data_get_content(&sd->block, &content);
	if (r != 0) {
	    break;
	}
    }
    end = xtimer_now();

    if (r == 0)
	printf("data_get_content finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("data_get_content failed\n");

    ndn_shared_block_release(sd);
}

static void test_interest_create(void)
{
    int repeat = 10000;
    printf("interest_create start (repeat=%d)\n", repeat);

    const char* uri = "/a/b/c/d";
    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("interest_create failed\n");
	return;
    }

    bool err = false;
    ndn_shared_block_t *sb;
    uint32_t begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	uint32_t lifetime = 0x4000;
	sb = ndn_interest_create(&sn->block, NULL, lifetime);
	if (sb == NULL) {
	    err = true;
	    break;
	}
	ndn_shared_block_release(sb);
    }
    uint32_t end = xtimer_now();

    ndn_shared_block_release(sn);

    if (!err)
	printf("interest_create finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("interest_create failed\n");
}

static void test_interest_get_name(void)
{
    int repeat = 1000000;
    printf("interest_get_name start (repeat=%d)\n", repeat);

    const char* uri = "/a/b/c/d";
    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("failed\n");
	return;
    }
    uint32_t lifetime = 0x4000;
    ndn_shared_block_t* sb = ndn_interest_create(&sn->block, NULL,
						 lifetime);
    ndn_shared_block_release(sn);
    if (sb == NULL) {
	printf("failed\n");
	return;
    }

    uint32_t begin = xtimer_now();
    ndn_block_t name;
    int r;
    for (int i = 0; i < repeat; ++i) {
	r = ndn_interest_get_name(&sb->block, &name);
	if (r != 0) {
	    break;
	}
    }
    uint32_t end = xtimer_now();

    if (r == 0)
	printf("interest_get_name finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("interest_get_name failed\n");

    ndn_shared_block_release(sb);
}

static void test_malloc(int sz)
{
    int repeat = 100000;
    printf("malloc %d start (repeat=%d)\n", sz, repeat);

    uint32_t begin = xtimer_now();
    void* p;
    bool err = false;
    for (int i = 0; i < repeat; ++i) {
	p = malloc(sz);
	if (p == NULL) {
	    err = true;
	    break;
	}
	free(p);
    }
    uint32_t end = xtimer_now();

    if (!err)
	printf("malloc %d finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n", sz,
	       end - begin, (end - begin) / repeat);
    else
	printf("malloc %d failed\n", sz);
}

static void test_memset(int sz)
{
    int repeat = 100000;
    printf("memset %d start (repeat=%d)\n", sz, repeat);

    uint8_t *src = (uint8_t*)malloc(sz);
    if (src == NULL) {
	printf("failed\n");
	return;
    }

    uint32_t begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	memset(src, i, sz);
    }
    uint32_t end = xtimer_now();

    free(src);

    printf("memset %d finished in %"PRIu32" us"
	   " (%"PRIu32" us on average)\n", sz,
	   end - begin, (end - begin) / repeat);
}

static void test_memcpy(int sz)
{
    int repeat = 100000;
    printf("memcpy %d start (repeat=%d)\n", sz, repeat);

    uint8_t *src = (uint8_t*)malloc(sz);
    if (src == NULL) {
	printf("failed\n");
	return;
    }
    memset(src, 0x11, sz);

    uint8_t *dst = (uint8_t*)malloc(sz);
    if (dst == NULL) {
	printf("failed\n");
	return;
    }

    uint32_t begin = xtimer_now();
    for (int i = 0; i < repeat; ++i) {
	memcpy(dst, src, sz);
    }
    uint32_t end = xtimer_now();

    free(src);
    free(dst);

    printf("memcpy %d finished in %"PRIu32" us"
	   " (%"PRIu32" us on average)\n", sz,
	   end - begin, (end - begin) / repeat);
}

int ndn_test(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s [name|interest|data]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "name") == 0) {
	test_name_from_uri();
	test_name_get_size();
	test_name_get_component();
	test_name_append();
    }
    else if (strcmp(argv[1], "interest") == 0) {
	test_interest_create();
	test_interest_get_name();
    }
    else if (strcmp(argv[1], "data") == 0) {
	test_data_create_digest();
	test_data_create_hmac();
	test_data_create_ecdsa();
	test_data_verify_ecdsa();
	test_data_get_name();
	test_data_get_content();
    }
    else if (strcmp(argv[1], "memory") == 0) {
	if (argc < 3) {
	    printf("usage: %s memory _size_\n", argv[0]);
	    return 1;
	}
	int s = atoi(argv[2]);
	test_malloc(s);
	test_memset(s);
	test_memcpy(s);
    }
    else {
        puts("error: invalid command");
    }
    return 0;
}
