#!/bin/sh

# Verbatim copy of Angora_original/tools/gen_library_abilist.sh (also present
# in the angora-reusing fork at tools/gen_library_abilist.sh) -- ported here
# so angora_dfsan_clang.sh's optional ANGORA_TAINT_RULE_LIST extra-abilist
# mechanism (mirroring angora_clang.c's own TAINT_RULE_LIST_VAR handling) can
# be generated the exact same way Angora-reusing's own benchmark build does,
# for a fair cross-fuzzer taint-log comparison on the same target binary.

if [ ! "$#" = "2" ]; then

    cat 1>&2 <<_EOF_
Usage
- Discard taints
$ ./gen_library_abilist.sh path-to-library.so > xxlib_abilist.txt discard
- Return value is the union of the label of its arguments.
$ ./gen_library_abilist.sh path-to-library.so > xxlib_abilist.txt functional
- Define a custom wrapper by yourself
$ ./gen_library_abilist.sh path-to-library.so > xxlib_abilist.txt custom
visit https://clang.llvm.org/docs/DataFlowSanitizer.html to see more.
_EOF_

    exit 1

fi

NM=`which nm 2>/dev/null`

if [ "$NM" = "" ]; then
    echo "[-] Error: can't find 'nm' in your \$PATH. please install binutils" 1>&2
    exit 1
fi

echo "# $1" | grep 'so[.0-9]*$'
if [ $? -eq 0 ]
then
    # echo "dynamic library.."
    nm -D --defined-only $1 | grep " T " | sed 's/^[0-9a-z]\+ T /fun:/g; s/$/=uninstrumented/g'
    nm -D --defined-only $1 | grep " T " | sed "s/^[0-9a-z]\+ T /fun:/g; s/$/=$2/g"
else
    # echo "static library.."
    nm --defined-only $1 | grep " T " | sed 's/^[0-9a-z]\+ T /fun:/g; s/$/=uninstrumented/g'
    nm --defined-only $1 | grep " T " | sed "s/^[0-9a-z]\+ T /fun:/g; s/$/=$2/g"
fi
