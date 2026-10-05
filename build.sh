#!/usr/bin/env sh
# Builds kaappu with nothing but a JDK (17 or newer). No Maven, no Gradle, no dependencies.
#   sh build.sh         compile and package build/kaappu.jar
#   sh build.sh test    compile and run the test suite
set -eu
cd "$(dirname "$0")"
rm -rf build
mkdir -p build/classes build/test-classes
javac --release 17 -Xlint:all -Werror -d build/classes $(find src -name '*.java')
if [ "${1:-}" = "test" ]; then
  javac --release 17 -cp build/classes -d build/test-classes $(find test -name '*.java')
  java -cp build/classes:build/test-classes kaappu.Tests
else
  jar --create --file build/kaappu.jar --main-class kaappu.Main -C build/classes .
  echo "Built build/kaappu.jar. Run: java -jar build/kaappu.jar help"
fi
