/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's parse_uint32_arg() string-to-uint32
 * parser. Called from parse_cli_args() to handle --cursor-color
 * (base 16). Sibling to fuzz_parse_uint31; same #include +
 * KLOAK_FUZZING approach.
 */

/*
 * See fuzz_parse_uint31.c for the design notes on why the
 * harnesses include src/kloak_parsers.inc.h rather than the
 * whole kloak.c (no wayland / libinput linkage in the fuzz
 * binary => no missing-shared-lib failures inside the OSS-Fuzz
 * run-fuzzers container).
 */
/* The pure helpers we test live in src/kloak.c. KLOAK_
 * FUZZ carves out the production sections (wayland /
 * libinput dispatch, globals, main) so this translation
 * unit only compiles the helpers + the struct types they
 * need. See the kloak.c header for details. */
#define KLOAK_FUZZ
#include "../src/kloak.c"
#include <stddef.h>

static const int kBases[] = {16, 10, 8, 2};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int base = 16;
  size_t slen = 0;
  char *buf = NULL;
  uint32_t out = 0;

  if (size < 1U) {
    return 0;
  }
  base = kBases[data[0] & 0x3];
  slen = size - 1U;

  buf = malloc(slen + 1U);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data + 1, slen);
  buf[slen] = '\0';

  (void)parse_uint32_arg(buf, base, &out);

  free(buf);
  return 0;
}
