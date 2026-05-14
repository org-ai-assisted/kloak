/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's handle_inotify_events(). The
 * function reads up to INOTIFY_READ_BUF_LEN bytes from
 * `inotify_fd` and walks the buffer as a sequence of
 * `struct inotify_event` records, dispatching to
 * attach_input_device / detach_input_device for any record whose
 * `name` matches "event". The interesting surface is:
 *   - the struct-walk arithmetic: rem_len bookkeeping, the
 *     `struct_len = sizeof(struct inotify_event) + ie->len`
 *     addition (ssize_t, -ftrapv on overflow), pointer advancement
 *   - the strncmp on the variable-length name field (OOB read
 *     surface for ASan if the name lacks a terminating null)
 *   - the kernel-contract asserts (rem_len >= sizeof header;
 *     ie->len bound; struct_len <= rem_len)
 *
 * The harness builds *structurally valid* event sequences from the
 * fuzz buffer (length prefix per event, bounded name length) so
 * the kernel-contract asserts hold and the fuzzer explores the
 * inner logic (name matching, mask branches, multi-event walking)
 * rather than tripping the asserts on every input.
 *
 * inotify_fd is swapped with a pipe; the fuzzer's bytes are
 * written into the pipe and read back through the regular read()
 * path. The attach/detach side-effects are #ifndef-guarded in
 * kloak.c so the harness does not need a live libinput context.
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#define MAX_NAME_LEN 64U

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *buf = NULL;
  size_t buf_used = 0;
  size_t cursor = 0;
  int pipefd[2] = { -1, -1 };
  int saved_inotify_fd = 0;
  ssize_t written = 0;
  uint8_t name_len_byte = 0;
  uint32_t mask = 0;
  size_t name_len = 0;
  struct inotify_event hdr = { 0 };

  if (size < 1U) {
    return 0;
  }

  /*
   * Worst case each fuzz event needs 1 byte header + 16 byte
   * struct inotify_event + MAX_NAME_LEN bytes of name. Cap the
   * accumulated buffer at INOTIFY_READ_BUF_LEN so the read() in
   * handle_inotify_events sees a single complete pass.
   */
  buf = calloc(INOTIFY_READ_BUF_LEN, 1U);
  if (buf == NULL) {
    return 0;
  }

  while (cursor < size) {
    /* Need at least 1 byte name length + 4 bytes mask. */
    if (size - cursor < 1U + sizeof(uint32_t)) {
      break;
    }
    name_len_byte = data[cursor++];
    name_len = (size_t)(name_len_byte) % (MAX_NAME_LEN + 1U);

    memcpy(&mask, data + cursor, sizeof(mask));
    cursor += sizeof(mask);

    if (size - cursor < name_len) {
      break;
    }
    if (buf_used + sizeof(struct inotify_event) + name_len
      > INOTIFY_READ_BUF_LEN) {
      break;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.wd = 1;
    hdr.mask = mask;
    hdr.cookie = 0;
    hdr.len = (uint32_t)name_len;
    memcpy(buf + buf_used, &hdr, sizeof(hdr));
    buf_used += sizeof(hdr);
    if (name_len > 0U) {
      memcpy(buf + buf_used, data + cursor, name_len);
      /*
       * Force null-termination of the name within its declared
       * length so strncmp / strlen inside handle_inotify_events do
       * not race past the declared end of the event.
       */
      buf[buf_used + name_len - 1U] = '\0';
      buf_used += name_len;
      cursor += name_len;
    }
  }

  if (buf_used == 0U) {
    free(buf);
    return 0;
  }

  if (pipe(pipefd) != 0) {
    free(buf);
    return 0;
  }

  written = write(pipefd[1], buf, buf_used);
  close(pipefd[1]);
  if (written < 0 || (size_t)written != buf_used) {
    close(pipefd[0]);
    free(buf);
    return 0;
  }

  saved_inotify_fd = inotify_fd;
  inotify_fd = pipefd[0];
  handle_inotify_events();
  inotify_fd = saved_inotify_fd;

  close(pipefd[0]);
  free(buf);
  return 0;
}
