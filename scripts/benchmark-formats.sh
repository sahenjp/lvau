#!/usr/bin/env bash
# Run on Linux/WSL2 after a release build; GNU time and coreutils are required.
set -euo pipefail

binary="${LVAU_BIN:-target/release/lvau-cli}"
if [[ ! -x "$binary" ]]; then
    printf 'Build the release CLI first: cargo build --locked --workspace --release\n' >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf 'benchmark-only-password\n' > "$work/password.txt"
chmod 600 "$work/password.txt"

printf 'format,size_mib,operation,run,seconds,cpu_percent,max_rss_kib,output_bytes\n'

measure() {
    local format="$1" size="$2" run="$3" operation="$4"
    local input="$work/input-${size}MiB.bin"
    local encrypted="$work/${format}-${size}-${run}.lvau"
    local output="$work/${format}-${size}-${run}.out"
    local metrics="$work/time.txt"
    local output_file
    local -a command

    if [[ "$operation" == encrypt ]]; then
        command=("$binary" encrypt --password --in-file "$input" --out-file "$encrypted" --password-file "$work/password.txt" --profile fast)
        if [[ "$format" == v3 ]]; then
            command+=(--format v3 --suite lv3-xc20p)
        fi
        output_file="$encrypted"
    else
        command=("$binary" decrypt --password --in-file "$encrypted" --out-file "$output" --password-file "$work/password.txt")
        output_file="$output"
    fi

    /usr/bin/time -f '%e %P %M' -o "$metrics" "${command[@]}" >/dev/null 2>&1
    read -r seconds cpu_percent max_rss_kib < "$metrics"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$format" "$size" "$operation" "$run" "$seconds" \
        "$cpu_percent" "$max_rss_kib" "$(stat -c %s "$output_file")"
}

for size in 1 256 1024; do
    dd if=/dev/zero of="$work/input-${size}MiB.bin" bs=1M count="$size" status=none
    for run in 1 2 3; do
        for format in v2 v3; do
            measure "$format" "$size" "$run" encrypt
            measure "$format" "$size" "$run" decrypt
            cmp "$work/input-${size}MiB.bin" "$work/${format}-${size}-${run}.out"
            rm -f "$work/${format}-${size}-${run}.lvau" "$work/${format}-${size}-${run}.out"
        done
    done
done
