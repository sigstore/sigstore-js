#!/usr/bin/env sh
set -e

if [ ! -d "/in" ]
then
  echo "Error: input directory for proto files /in does not exist"
  exit 1
fi

if [ ! -d "/out" ]
then
  echo "Error: output directory /out does not exist"
  exit 1
fi

protoc --plugin=/usr/local/bin/protoc-gen-ts \
  --ts_proto_out=/out \
  --ts_proto_opt=forceLong=string \
  --ts_proto_opt=env=node \
  --ts_proto_opt=outputJsonMethods=true \
  --ts_proto_opt=outputEncodeMethods=false \
  --ts_proto_opt=outputPartialMethods=false \
  --ts_proto_opt=oneof=unions \
  --ts_proto_opt=unrecognizedEnum=false \
  --ts_proto_opt=exportCommonSymbols=false \
  -I /in \
  "$@"
