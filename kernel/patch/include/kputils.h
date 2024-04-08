/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_UTILS_H_
#define _KP_UTILS_H_

#include <compiler.h>
#include <ktypes.h>

unsigned long __must_check kp_copy_from_user(void *to, const void __user *from, unsigned long n);

unsigned long __must_check kp_copy_to_user(void __user *to, const void *from, unsigned long n);

int __must_check compat_copy_to_user(void __user *to, const void *from, int n);

void *__user copy_to_user_stack(const void *data, int len);

uint64_t get_random_u64(void);

void print_bootlog();

#endif