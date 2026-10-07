#!/usr/bin/env bash

if [ -t 1 ]; then
  COLOR_RED=$'\033[31m'; COLOR_GREEN=$'\033[32m'; COLOR_YELLOW=$'\033[33m'
  COLOR_CYAN=$'\033[36m'; COLOR_BOLD=$'\033[1m'; COLOR_RESET=$'\033[0m'
else
  COLOR_RED=''; COLOR_GREEN=''; COLOR_YELLOW=''; COLOR_CYAN=''; COLOR_BOLD=''; COLOR_RESET=''
fi

is_verify_disabled() {
  [ "${WIFISEC_NO_VERIFY:-0}" = "1" ]
}

is_merge_commit() {
  [ -f "$(git rev-parse --git-dir)/MERGE_HEAD" ]
}

info()  { printf '%s[wifisec]%s %s\n' "${COLOR_CYAN}${COLOR_BOLD}" "${COLOR_RESET}" "$*"; }
ok()    { printf '%s[wifisec]%s %s✔ %s\n' "${COLOR_GREEN}${COLOR_BOLD}" "${COLOR_RESET}" "${COLOR_GREEN}" "$*${COLOR_RESET}"; }
warn()  { printf '%s[wifisec]%s %s警告%s：%s\n' "${COLOR_YELLOW}${COLOR_BOLD}" "${COLOR_RESET}" "${COLOR_YELLOW}" "${COLOR_RESET}" "$*" >&2; }
err()   { printf '%s[wifisec]%s %s错误%s：%s\n' "${COLOR_RED}${COLOR_BOLD}" "${COLOR_RESET}" "${COLOR_RED}" "${COLOR_RESET}" "$*" >&2; }

explain() {
  printf '%s\n' "${COLOR_YELLOW}"
  printf '  ┌─────────────────────────────────────────────────────────────┐\n'
  while IFS= read -r line; do
    printf '  │ %-59s │\n' "$line"
  done
  printf '  └─────────────────────────────────────────────────────────────┘%s\n' "${COLOR_RESET}"
  printf '\n' >&2
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

staged_files() {
  git diff --cached --name-only --diff-filter=ACM
}

blob_to_file() {
  local path="$1" out="$2"
  git show ":$path" >"$out" 2>/dev/null
}
