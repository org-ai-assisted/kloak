/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for esc_combo_update(), the pure panic-key
 * state-machine update factored out of register_esc_combo_event()
 * in kloak.c. Production caller exits the process on a fully-
 * held combo; the harness only observes the return value, so a
 * crashing input here reflects a real state-machine bug rather
 * than the expected panic-exit.
 *
 * Input format: first 1 byte selects which esc_key combo to
 * preconfigure (a couple of canned shapes - one-key, two-key,
 * two-token-OR). Remaining bytes are a stream of (uint32_t key,
 * bool pressed) pairs replayed against esc_combo_update. Active
 * mask is reset between iterations; the preconfigured combo
 * itself stays.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Stubs required by parse_esc_key_str's body, which we use only
 * for one-time combo setup in LLVMFuzzerInitialize. */
static char *safe_strdup(const char *s) {
  char *r = strdup(s);
  if (r == NULL) abort();
  return r;
}
static void *safe_reallocarray(void *ptr, size_t nmemb, size_t size) {
  void *r = reallocarray(ptr, nmemb, size);
  if (r == NULL) abort();
  return r;
}

#define KLOAK_INCLUDE_ESC_KEY_PARSER
#include "../src/kloak_parsers.inc.h"

/* Pre-built esc_key state for each combo shape. Built once at
 * init; never freed (harness lifetime). Indexed by data[0] & 3. */
struct combo_setup {
  const char *spec;
  uint32_t **list;
  size_t *sublist_lens;
  bool *active;
  size_t list_len;
};

static struct combo_setup g_combos[4];

static void build_combo(size_t idx, const char *spec) {
  /* parse_esc_key_str mutates the four globals; capture them
   * into the per-combo slot then reset the globals so the next
   * setup starts clean. */
  esc_key_list = NULL;
  esc_key_sublist_len = NULL;
  active_esc_key_list = NULL;
  esc_key_list_len = 0;
  if (!parse_esc_key_str(spec)) {
    abort();
  }
  g_combos[idx].spec = spec;
  g_combos[idx].list = esc_key_list;
  g_combos[idx].sublist_lens = esc_key_sublist_len;
  g_combos[idx].active = active_esc_key_list;
  g_combos[idx].list_len = esc_key_list_len;
  /* Detach from globals so reset_esc_key_state does not free. */
  esc_key_list = NULL;
  esc_key_sublist_len = NULL;
  active_esc_key_list = NULL;
  esc_key_list_len = 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  build_combo(0, "KEY_ESC");
  build_combo(1, "KEY_RIGHTSHIFT,KEY_ESC");
  build_combo(2, "KEY_LEFTSHIFT|KEY_RIGHTSHIFT,KEY_ESC");
  build_combo(3, "KEY_A|KEY_B|KEY_C,KEY_D,KEY_E");
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct combo_setup *c = NULL;
  size_t i = 0;
  size_t pos = 1;
  uint32_t key = 0;
  bool pressed = false;

  if (size < 1U) {
    return 0;
  }
  c = &g_combos[data[0] & 0x3];
  if (c->list == NULL) {
    return 0;
  }
  /* Reset the active mask for this combo before replaying the
   * event stream so iterations do not bleed state. */
  for (i = 0; i < c->list_len; i++) {
    c->active[i] = false;
  }

  while (pos + sizeof(uint32_t) + 1U <= size) {
    memcpy(&key, data + pos, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    pressed = (data[pos] & 0x1) != 0;
    pos += 1;
    (void)esc_combo_update(key, pressed,
      c->list, c->sublist_lens, c->list_len, c->active);
  }
  return 0;
}
