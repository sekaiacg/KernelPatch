/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <fcntl.h>
#include <unistd.h>

#include "common.h"
#include "order.h"

bool log_enable = false;

int can_b_imm(uint64_t from, uint64_t to)
{
    // B: 128M
    uint32_t imm26 = 1 << 25 << 2;
    return (to >= from && to - from <= imm26) || (from >= to && from - to <= imm26);
}

int b(uint32_t *buf, uint64_t from, uint64_t to)
{
    if (can_b_imm(from, to)) {
        buf[0] = 0x14000000u | (((to - from) & 0x0FFFFFFFu) >> 2u);
        return 4;
    }
    return 0;
}

int32_t relo_branch_func(const char *img, int32_t func_offset)
{
    uint32_t inst = *(uint32_t *)(img + func_offset);
    int32_t relo_offset = func_offset;
    if (INSN_IS_B(inst)) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        relo_offset = func_offset + (int32_t)imm64;
        tools_logi("relocate branch function 0x%x to 0x%x\n", func_offset, relo_offset);
    }
    return relo_offset;
}

void read_file_align(const char *path, char **con, int *out_len, int align)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) tools_log_errno_exit("open file %s\n", path);
    fseek(fp, 0, SEEK_END);
    int len = (int)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    int align_len = (int)align_ceil(len, align);
    char *buf = (char *)malloc(align_len);
    memset(buf + len, 0, align_len - len);
    int readlen = fread(buf, 1, len, fp);
    if (readlen != len) tools_log_errno_exit("read file %s\n", path);
    fclose(fp);
    *con = buf;
    *out_len = align_len;
}

void write_file(const char *path, const char *con, int len, bool append)
{
    FILE *fout = fopen(path, append ? "ab" : "wb");
    if (!fout) tools_log_errno_exit("open file %s\n", path);
    int writelen = fwrite(con, 1, len, fout);
    if (writelen != len) tools_log_errno_exit("write file %s\n", path);
    fclose(fout);
}

int32_t get_file_size(const char *path)
{
    FILE *fout = fopen(path, "rb");
    if (!fout) tools_log_errno_exit("open file %s\n", path);
    fseek(fout, 0, SEEK_END);
    int32_t len = ftell(fout);
    fclose(fout);
    if (len > 0) return len;
    tools_log_errno_exit("fail get file size: %s\n", path);
}

#if defined(_WIN32)

// Non Thread Safe
inline static ssize_t pread(int fd, void *buf, size_t n, off64_t offset)
{
    off64_t cur_pos;
    ssize_t num_read;

    if ((cur_pos = lseek(fd, 0, SEEK_CUR)) == (off64_t)-1) return -1;

    if (lseek(fd, offset, SEEK_SET) == (off64_t)-1) return -1;

    num_read = read(fd, buf, n);

    if (lseek(fd, cur_pos, SEEK_SET) == (off64_t)-1) return -1;
    return (ssize_t)num_read;
}

#endif

inline static int _file_read(int fd, void *buf, uint64_t offset, size_t len)
{
    ssize_t read_count;

    if (!buf) {
        return -EINVAL;
    }

    while (len > 0) {
        read_count = pread(fd, buf, len, offset);
        if (read_count < 1) {
            if (!read_count) {
                return 0;
            } else if (errno != EINTR) {
                return -errno;
            }
        }
        offset += read_count;
        len -= read_count;
        buf = (char *)buf + read_count;
    }
    return 0;
}

int file_read(const char *path, void *buf, uint64_t offset, size_t len)
{
    int fd = open(path, O_RDONLY | O_BINARY);
    if (fd > 0) {
        int ret = _file_read(fd, buf, offset, len);
        close(fd);
        if (ret) tools_log_errno_exit("read file %s\n", path);
        return ret;
    }
    tools_log_errno_exit("open file %s\n", path);
}

int64_t int_unpack(void *ptr, int32_t size, bool is_be)
{
    bool swp = is_be ^ is_be();
    int64_t res64;
    int32_t res32;
    int16_t res16;
    switch (size) {
    case 8:
        res64 = *(int64_t *)ptr;
        return swp ? i64swp(res64) : res64;
    case 4:
        res32 = *(int32_t *)ptr;
        return swp ? i32swp(res32) : res32;
    case 2:
        res16 = *(int16_t *)ptr;
        return swp ? i16swp(res16) : res16;
    default:
        return *(int8_t *)ptr;
    }
}

uint64_t uint_unpack(void *ptr, int32_t size, bool is_be)
{
    bool swp = is_be ^ is_be();
    uint64_t res64;
    uint32_t res32;
    uint16_t res16;
    switch (size) {
    case 8:
        res64 = *(uint64_t *)ptr;
        return swp ? u64swp(res64) : res64;
    case 4:
        res32 = *(uint32_t *)ptr;
        return swp ? u32swp(res32) : res32;
    case 2:
        res16 = *(uint16_t *)ptr;
        return swp ? u16swp(res16) : res16;
    default:
        return *(uint8_t *)ptr;
    }
}
