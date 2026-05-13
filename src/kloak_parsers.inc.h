/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure-parser surface for kloak's CLI. Included by both
 * src/kloak.c and by the libFuzzer harnesses in fuzz/. By design
 * the functions here are exit()-free (return bool / 0 on bad
 * input - see kloak.c:892's comment from before this split) so
 * they can be fuzzed in isolation. The fuzz harness binary picks
 * up only this header's content and thus has zero transitive
 * libinput / wayland linkage, which is what lets it run inside
 * the OSS-Fuzz ClusterFuzzLite run-fuzzers container (which
 * ships only libc-class runtime libs).
 *
 * Single source of truth: editing the parsers / key table here
 * is automatically picked up by both kloak proper (via kloak.c's
 * #include) and the fuzz harnesses.
 *
 * The functions are 'static' so each translation unit that
 * #include's this header gets its own private copy with internal
 * linkage. No name-collision risk when linking the harnesses
 * against the wayland-scanner-generated protocol .c files (which
 * never reference these symbols).
 */

#ifndef KLOAK_PARSERS_INC_H
#define KLOAK_PARSERS_INC_H

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/input-event-codes.h>

/*
 * Defines an evdev key code and the corresponding string.
 */
struct key_name_value {
    const char *name;
    const uint32_t value;
};

static struct key_name_value key_table[] = {
  {"KEY_ESC", KEY_ESC},
  {"KEY_1", KEY_1},
  {"KEY_2", KEY_2},
  {"KEY_3", KEY_3},
  {"KEY_4", KEY_4},
  {"KEY_5", KEY_5},
  {"KEY_6", KEY_6},
  {"KEY_7", KEY_7},
  {"KEY_8", KEY_8},
  {"KEY_9", KEY_9},
  {"KEY_0", KEY_0},
  {"KEY_MINUS", KEY_MINUS},
  {"KEY_EQUAL", KEY_EQUAL},
  {"KEY_BACKSPACE", KEY_BACKSPACE},
  {"KEY_TAB", KEY_TAB},
  {"KEY_Q", KEY_Q},
  {"KEY_W", KEY_W},
  {"KEY_E", KEY_E},
  {"KEY_R", KEY_R},
  {"KEY_T", KEY_T},
  {"KEY_Y", KEY_Y},
  {"KEY_U", KEY_U},
  {"KEY_I", KEY_I},
  {"KEY_O", KEY_O},
  {"KEY_P", KEY_P},
  {"KEY_LEFTBRACE", KEY_LEFTBRACE},
  {"KEY_RIGHTBRACE", KEY_RIGHTBRACE},
  {"KEY_ENTER", KEY_ENTER},
  {"KEY_LEFTCTRL", KEY_LEFTCTRL},
  {"KEY_A", KEY_A},
  {"KEY_S", KEY_S},
  {"KEY_D", KEY_D},
  {"KEY_F", KEY_F},
  {"KEY_G", KEY_G},
  {"KEY_H", KEY_H},
  {"KEY_J", KEY_J},
  {"KEY_K", KEY_K},
  {"KEY_L", KEY_L},
  {"KEY_SEMICOLON", KEY_SEMICOLON},
  {"KEY_APOSTROPHE", KEY_APOSTROPHE},
  {"KEY_GRAVE", KEY_GRAVE},
  {"KEY_LEFTSHIFT", KEY_LEFTSHIFT},
  {"KEY_BACKSLASH", KEY_BACKSLASH},
  {"KEY_Z", KEY_Z},
  {"KEY_X", KEY_X},
  {"KEY_C", KEY_C},
  {"KEY_V", KEY_V},
  {"KEY_B", KEY_B},
  {"KEY_N", KEY_N},
  {"KEY_M", KEY_M},
  {"KEY_COMMA", KEY_COMMA},
  {"KEY_DOT", KEY_DOT},
  {"KEY_SLASH", KEY_SLASH},
  {"KEY_RIGHTSHIFT", KEY_RIGHTSHIFT},
  {"KEY_KPASTERISK", KEY_KPASTERISK},
  {"KEY_LEFTALT", KEY_LEFTALT},
  {"KEY_SPACE", KEY_SPACE},
  {"KEY_CAPSLOCK", KEY_CAPSLOCK},
  {"KEY_F1", KEY_F1},
  {"KEY_F2", KEY_F2},
  {"KEY_F3", KEY_F3},
  {"KEY_F4", KEY_F4},
  {"KEY_F5", KEY_F5},
  {"KEY_F6", KEY_F6},
  {"KEY_F7", KEY_F7},
  {"KEY_F8", KEY_F8},
  {"KEY_F9", KEY_F9},
  {"KEY_F10", KEY_F10},
  {"KEY_NUMLOCK", KEY_NUMLOCK},
  {"KEY_SCROLLLOCK", KEY_SCROLLLOCK},
  {"KEY_KP7", KEY_KP7},
  {"KEY_KP8", KEY_KP8},
  {"KEY_KP9", KEY_KP9},
  {"KEY_KPMINUS", KEY_KPMINUS},
  {"KEY_KP4", KEY_KP4},
  {"KEY_KP5", KEY_KP5},
  {"KEY_KP6", KEY_KP6},
  {"KEY_KPPLUS", KEY_KPPLUS},
  {"KEY_KP1", KEY_KP1},
  {"KEY_KP2", KEY_KP2},
  {"KEY_KP3", KEY_KP3},
  {"KEY_KP0", KEY_KP0},
  {"KEY_KPDOT", KEY_KPDOT},
  {"KEY_ZENKAKUHANKAKU", KEY_ZENKAKUHANKAKU},
  {"KEY_102ND", KEY_102ND},
  {"KEY_F11", KEY_F11},
  {"KEY_F12", KEY_F12},
  {"KEY_RO", KEY_RO},
  {"KEY_KATAKANA", KEY_KATAKANA},
  {"KEY_HIRAGANA", KEY_HIRAGANA},
  {"KEY_HENKAN", KEY_HENKAN},
  {"KEY_KATAKANAHIRAGANA", KEY_KATAKANAHIRAGANA},
  {"KEY_MUHENKAN", KEY_MUHENKAN},
  {"KEY_KPJPCOMMA", KEY_KPJPCOMMA},
  {"KEY_KPENTER", KEY_KPENTER},
  {"KEY_RIGHTCTRL", KEY_RIGHTCTRL},
  {"KEY_KPSLASH", KEY_KPSLASH},
  {"KEY_SYSRQ", KEY_SYSRQ},
  {"KEY_RIGHTALT", KEY_RIGHTALT},
  {"KEY_LINEFEED", KEY_LINEFEED},
  {"KEY_HOME", KEY_HOME},
  {"KEY_UP", KEY_UP},
  {"KEY_PAGEUP", KEY_PAGEUP},
  {"KEY_LEFT", KEY_LEFT},
  {"KEY_RIGHT", KEY_RIGHT},
  {"KEY_END", KEY_END},
  {"KEY_DOWN", KEY_DOWN},
  {"KEY_PAGEDOWN", KEY_PAGEDOWN},
  {"KEY_INSERT", KEY_INSERT},
  {"KEY_DELETE", KEY_DELETE},
  {"KEY_MACRO", KEY_MACRO},
  {"KEY_MUTE", KEY_MUTE},
  {"KEY_VOLUMEDOWN", KEY_VOLUMEDOWN},
  {"KEY_VOLUMEUP", KEY_VOLUMEUP},
  {"KEY_POWER", KEY_POWER},
  {"KEY_POWER2", KEY_POWER2},
  {"KEY_KPEQUAL", KEY_KPEQUAL},
  {"KEY_KPPLUSMINUS", KEY_KPPLUSMINUS},
  {"KEY_PAUSE", KEY_PAUSE},
  {"KEY_SCALE", KEY_SCALE},
  {"KEY_KPCOMMA", KEY_KPCOMMA},
  {"KEY_HANGEUL", KEY_HANGEUL},
  {"KEY_HANGUEL", KEY_HANGUEL},
  {"KEY_HANJA", KEY_HANJA},
  {"KEY_YEN", KEY_YEN},
  {"KEY_LEFTMETA", KEY_LEFTMETA},
  {"KEY_RIGHTMETA", KEY_RIGHTMETA},
  {"KEY_COMPOSE", KEY_COMPOSE},
  {"KEY_F13", KEY_F13},
  {"KEY_F14", KEY_F14},
  {"KEY_F15", KEY_F15},
  {"KEY_F16", KEY_F16},
  {"KEY_F17", KEY_F17},
  {"KEY_F18", KEY_F18},
  {"KEY_F19", KEY_F19},
  {"KEY_F20", KEY_F20},
  {"KEY_F21", KEY_F21},
  {"KEY_F22", KEY_F22},
  {"KEY_F23", KEY_F23},
  {"KEY_F24", KEY_F24},
  {"KEY_UNKNOWN", KEY_UNKNOWN},
  {NULL, 0}
};

/*
 * Both this and parse_uint32_arg make it the caller's responsibility to
 * terminate the application if the parse fails. This it to make it easier to
 * fuzz kloak.
 */
static bool parse_uint31_arg(const char *val, int base, int32_t *out) {
  char *val_endchar = NULL;
  uint64_t val_int = 0;

  if (val == NULL || out == NULL) {
    return false;
  }
  if (*val == '\0') {
    return false;
  }
  errno = 0;
  val_int = strtoul(val, &val_endchar, base);
  if (errno == ERANGE) {
    return false;
  }
  if (*val_endchar != '\0') {
    return false;
  }
  if (val_int > INT32_MAX) {
    return false;
  }
  *out = (int32_t)(val_int);
  return true;
}

static bool parse_uint32_arg(const char *val, int base, uint32_t *out) {
  char *val_endchar = NULL;
  uint64_t val_int = 0;

  if (val == NULL || out == NULL) {
    return false;
  }
  if (*val == '\0') {
    return false;
  }
  errno = 0;
  val_int = strtoul(val, &val_endchar, base);
  if (errno == ERANGE) {
    return false;
  }
  if (*val_endchar != '\0') {
    return false;
  }
  if (val_int > UINT32_MAX) {
    return false;
  }
  *out = (uint32_t)(val_int);
  return true;
}

static uint32_t lookup_keycode(const char *name) {
  struct key_name_value *p = NULL;

  for (p = key_table; p->name != NULL; p++) {
    if (strcmp(p->name, name) == 0) {
      return p->value;
    }
  }
  return 0;
}

/*
 * parse_esc_key_str() parses the --esc-keys CLI argument's value
 * (a comma-separated list of pipe-separated key-name groups, e.g.
 * "KEY_LEFTSHIFT|KEY_RIGHTSHIFT,KEY_ESC") into the four module-
 * scope globals below. Returns false on the first malformed token
 * (empty entry, unknown key name); the caller is responsible for
 * terminating the process. Designed exit()-free so it can be a
 * libFuzzer target; see fuzz/fuzz_parse_esc_key_str.c.
 *
 * The block is gated by KLOAK_INCLUDE_ESC_KEY_PARSER so the three
 * simple-parser harnesses (fuzz_parse_uint31 / fuzz_parse_uint32
 * / fuzz_lookup_keycode) - which do not call parse_esc_key_str -
 * skip the safe_strdup / safe_reallocarray forward decls and
 * avoid -Wundefined-internal warnings for those symbols.
 */
#ifdef KLOAK_INCLUDE_ESC_KEY_PARSER

/*
 * Forward-declare safe_strdup / safe_reallocarray so the parser
 * body below compiles in any consuming TU. Each consuming TU
 * supplies its own definitions: kloak.c has the production
 * versions (abort on OOM with a FATAL ERROR message), the fuzz
 * harness supplies minimal abort()-on-OOM stubs.
 */
static char *safe_strdup(const char *s);
static void *safe_reallocarray(void *ptr, size_t nmemb, size_t size);

static uint32_t **esc_key_list = NULL;
static size_t *esc_key_sublist_len = NULL;
static bool *active_esc_key_list = NULL;
static size_t esc_key_list_len = 0;

static bool parse_esc_key_str(const char *esc_key_str) {
  char *esc_key_str_copy = safe_strdup(esc_key_str);
  char *orig_key_str_copy = esc_key_str_copy;
  char *root_token = NULL;
  const char *sub_token = NULL;
  size_t i = 0;
  size_t j = 0;

  for (i = 0; ((root_token = strsep(&esc_key_str_copy, ",")) != NULL); i++) {
    if (root_token[0] == '\0' ) {
      fprintf(stderr,
        "FATAL ERROR: Empty key name specified in escape key list!\n");
      free(orig_key_str_copy);
      return false;
    }

    esc_key_list_len++;
    esc_key_list = safe_reallocarray(esc_key_list, esc_key_list_len,
      sizeof(uint32_t *));
    esc_key_sublist_len = safe_reallocarray(esc_key_sublist_len,
      esc_key_list_len, sizeof(size_t));
    active_esc_key_list = safe_reallocarray(active_esc_key_list,
      esc_key_list_len, sizeof(bool));
    esc_key_list[i] = NULL;
    esc_key_sublist_len[i] = 0;
    active_esc_key_list[i] = false;

    for (j = 0; ((sub_token = strsep(&root_token, "|")) != NULL); j++)  {
      if (sub_token[0] == '\0') {
        fprintf(stderr,
          "FATAL ERROR: Empty key name specified in escape key list!\n");
        free(orig_key_str_copy);
        return false;
      }

      esc_key_sublist_len[i]++;
      esc_key_list[i] = safe_reallocarray(esc_key_list[i],
        esc_key_sublist_len[i], sizeof(uint32_t));
      esc_key_list[i][j] = lookup_keycode(sub_token);
      if (esc_key_list[i][j] == 0) {
        fprintf(stderr, "FATAL ERROR: Unrecognized Key name '%s'!\n",
          sub_token);
        free(orig_key_str_copy);
        return false;
      }
    }
  }

  free(orig_key_str_copy);
  return true;
}

/*
 * reset_esc_key_state() releases everything parse_esc_key_str()
 * allocated into the four globals above and zeroes them, so a
 * subsequent parse starts from a clean slate. The production
 * binary parses --esc-keys exactly once and never calls this;
 * libFuzzer harnesses call it between iterations to avoid
 * unbounded memory growth.
 */
static void reset_esc_key_state(void) __attribute__((unused));
static void reset_esc_key_state(void) {
  for (size_t k = 0; k < esc_key_list_len; k++) {
    free(esc_key_list[k]);
  }
  free(esc_key_list);
  esc_key_list = NULL;
  free(esc_key_sublist_len);
  esc_key_sublist_len = NULL;
  free(active_esc_key_list);
  active_esc_key_list = NULL;
  esc_key_list_len = 0;
}

#endif /* KLOAK_INCLUDE_ESC_KEY_PARSER */

#endif /* KLOAK_PARSERS_INC_H */
