#!/bin/bash

fail() {
    echo "\e[31mSTEP FAIL\e[0m"
    TEST_FAILURE=1
}

TEST_FAILURE=0

report() {
    echo "----------------------------------------"
    if [ $TEST_FAILURE -eq 0 ]; then
        echo "\e[32mTEST PASS\e[0m"
    echo "----------------------------------------"
    else
        echo "\e[31mTEST FAIL\e[0m"
    echo "----------------------------------------"
        exit 1
    fi
}