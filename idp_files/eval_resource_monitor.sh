#!/bin/bash
record_path="/home/nruntemund/ba_program/logs/resource_usage.txt";
cg_path="/sys/fs/cgroup/system.slice"
ram_pattern="^anon [0-9]|^file [0-9]|^kernel [0-9]"
kc_con="$1"
pg_con="$2"
cd_con="$3"

function cio_tf() {
    echo -n "$1 $2 " >> $record_path;
    date +%s%N >> $record_path;
    cat "$3"/"$2".stat >> $record_path;
    echo "+---+" >> $record_path;
}

function mem_tf() {
    echo -n "$1 memory " >> $record_path;
    date +%s%N >> $record_path;
    cat "$2"/memory.stat | grep -E "$ram_pattern" >> $record_path;
    echo "+---+" >> $record_path;
}

while true; do
    cio_tf "docker" "cpu" "$cg_path";
    cio_tf "keycloak" "cpu" "$cg_path/$kc_con";
    cio_tf "postgres" "cpu" "$cg_path/$pg_con";
    cio_tf "caddy" "cpu" "$cg_path/$cd_con";

    mem_tf "docker" "$cg_path";
    mem_tf "keycloak" "$cg_path/$kc_con";
    mem_tf "postgres" "$cg_path/$pg_con";
    mem_tf "caddy" "$cg_path/$cd_con";

    cio_tf "docker" "io" "$cg_path";
    cio_tf "keycloak" "io" "$cg_path/$kc_con";
    cio_tf "postgres" "io" "$cg_path/$pg_con";
    cio_tf "caddy" "io" "$cg_path/$cd_con";

    sleep 1;
done;
