#!/bin/bash
record_path="/home/nruntemund/ba_program/logs/resource_usage.txt";
cg_path="/sys/fs/cgroup/eval.slice"
ram_pattern="^anon [0-9]|^file [0-9]|^kernel [0-9]"

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
    cio_tf "eval.slice" "cpu" "$cg_path";
    cio_tf "nginx" "cpu" "$cg_path/nginx.service";
    cio_tf "gunicorn" "cpu" "$cg_path/gunicorn.service";

    mem_tf "eval.slice" "$cg_path";
    mem_tf "nginx" "$cg_path/nginx.service";
    mem_tf "gunicorn" "$cg_path/gunicorn.service";

    cio_tf "eval.slice" "io" "$cg_path";
    cio_tf "nginx" "io" "$cg_path";
    cio_tf "gunicorn" "io" "$cg_path";
    
    sleep 1;
done;
