#!/bin/sh
# Rebuilds the API contract fixtures. Needs protoc 29.3, protoc-gen-go v1.36.5, Go 1.23, python3.
# Outputs: ../../contracts/revdemo-go.elf.gz, revdemo_pb2.py, revdemo_pb2.pyc, revdemo.desc
set -e
cd "$(dirname "$0")"
OUT=../../contracts
INC=${PROTOC_INCLUDE:-/workspace/work/tools/protoc/include}
mkdir -p gen $OUT
protoc -I. -I"$INC" --go_out=gen --go_opt=paths=source_relative revdemo.proto
protoc -I. -I"$INC" --python_out=$OUT revdemo.proto
protoc -I. -I"$INC" --descriptor_set_out=$OUT/revdemo.desc revdemo.proto
python3 -c "import py_compile;py_compile.compile('$OUT/revdemo_pb2.py',cfile='$OUT/revdemo_pb2.pyc',doraise=True)"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $OUT/revdemo-go.elf .
gzip -9 -f $OUT/revdemo-go.elf
