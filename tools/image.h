/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_IMAGE_H_
#define _KP_TOOL_IMAGE_H_

#include <stdint.h>

// /arch/arm64/kernel/head.S

#define UNCOMPRESSED_IMG_MAGIC "UNCOMPRESSED_IMG"
#define UNCOMPRESSED_IMG_MAGIC_LEN 16

typedef struct
{
    int32_t arch;
    int8_t is_64;
    int8_t is_be; // 0: little, 1: big
    int8_t uefi; //
    int32_t load_offset;
    int32_t kernel_size;
    int32_t page_shift;
    int32_t b_stext_insn_offset;
    int32_t primary_entry_offset;

    int32_t is_uncompressed_img;
    int32_t kimg_offset;
    int32_t kimg_real_size;
    int32_t dtb_offset;
} kernel_info_t;

void readKernelImage(kernel_info_t *kinfo, const char *path, char **con, int *len);
void appendImageHeader(const kernel_info_t *kinfo, const char *path);
int32_t get_kernel_info(kernel_info_t *kinfo, const char *img, int32_t imglen);
int32_t kernel_resize(kernel_info_t *kinfo, char *img, int32_t size);

#endif
