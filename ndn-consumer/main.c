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
 * @author      Wentao Shang <wentaoshang@gmaiil.com>
 *
 * @}
 */

#include <stdio.h>

extern void ndn_consumer(void);

int main(void)
{
    ndn_consumer();

    /* should be never reached */
    return 0;
}
