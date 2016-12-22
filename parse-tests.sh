#!/bin/sh
# Copyright (c) 2016 Uber Technologies, Inc.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# A simple script to parse the output of test.sql during `make test'. Exits
# successfully only if all tests pass.

test_count=0
line_count=0
pass_count=0

while IFS='|' read testcase description expected error_expected rest; do
    line_count=$(($line_count + 1))

    case "$testcase" in
        HINT:*)
            continue
            ;;
        TESTCASE)
            ;;
        *)
            echo "Unexpected test output at line $line_count"
            echo "$testcase"
            exit 1
    esac

    test_count=$(($test_count + 1))
    echo "Test $test_count: $description"

    while true; do
        if ! read actual; then
            echo "Unexpected end of test output at line $line_count"
            exit 1
        fi
        line_count=$(($line_count + 1))
        case "$actual" in
            HINT:*)
                continue
                ;;
            *)
                break
                ;;
        esac
    done

    if [ "$error_expected" = 't' ]; then
        expected='*ERROR*:*'
    fi

    case "$actual" in
        $expected)
            echo "    PASS"
            pass_count=$(($pass_count + 1))
            ;;
        *)
            echo "    FAIL"
            echo "    Expected: $expected"
            echo "    Got: $actual"
            ;;
    esac
done

echo "$test_count tests were run."
echo "$pass_count tests passed."
echo "$(($test_count - $pass_count)) tests failed."

exit $(($test_count - $pass_count))
