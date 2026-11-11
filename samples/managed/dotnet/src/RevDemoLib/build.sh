#!/bin/sh
# Builds RevDemoLib-1.0.0.dll and RevDemoLib-2.0.0.dll with the .NET 8 SDK (8.0.428), Release, deterministic.
set -e
cd "$(dirname "$0")"
for v in 1.0.0 2.0.0; do
  rm -rf obj bin
  dotnet build -c Release -p:RevDemoVersion=$v -o /tmp/rdl-$v
  cp /tmp/rdl-$v/RevDemoLib.dll ../../RevDemoLib-$v.dll
done
rm -rf obj bin
