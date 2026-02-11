node tests/direct_compare/compare_implementations.mjs rules/literals.yar test_files/literals.txt  

node tests/direct_compare/compare_implementations.mjs rules/literals.yar test_files/literals_wide.txt  

node tests/direct_compare/compare_implementations.mjs rules/base64_tests.yar test_files/base64_tests.txt

# Still some differences in regex matching due to implementation differences for UTF-16
node tests/direct_compare/compare_implementations.mjs rules/regex.yar test_files/regex.txt

node tests/direct_compare/compare_implementations.mjs rules/hex.yar test_files/hex.bin

node tests/direct_compare/compare_implementations.mjs rules/hex.yar test_files/hex.txt

node tests/direct_compare/compare_implementations.mjs rules/ruleMods.yar test_files/ruleMods.txt

node tests/testGlobalRules.mjs

node tests/direct_compare/compare_implementations.mjs rules/conditions.yar test_files/conditions.txt

node tests/direct_compare/compare_implementations.mjs rules/conditions.yar test_files/conditions.bin

# Test module support (Math, Hash, String, Time)
node tests/direct_compare/compare_implementations.mjs rules/modules.yar test_files/modules.bin
node tests/direct_compare/compare_implementations.mjs rules/modules.yar test_files/modules.txt

node tests/direct_compare/compare_implementations.mjs rules/elf_tests.yar test_files/test_elf32.bin
node tests/direct_compare/compare_implementations.mjs rules/elf_tests.yar test_files/test_elf64.bin

node tests/direct_compare/compare_implementations.mjs rules/pe_tests.yar test_files/test_pe32.exe
node tests/direct_compare/compare_implementations.mjs rules/pe_tests.yar test_files/test_pe64.exe

node tests/direct_compare/compare_implementations.mjs rules/pe_tests_extended.yar test_files/test_pe32.exe
node tests/direct_compare/compare_implementations.mjs rules/pe_tests_extended.yar test_files/test_pe64.exe

node tests/direct_compare/compare_implementations.mjs rules/test_string_operators.yar test_files/test_pe32.exe

# node tests/direct_compare/node_yara_runner.js --rulefile rules/pe_tests.yar --file test_files/test_pe32.bin
# python tests/direct_compare/py_yara_runner.py --rulefile rules/elf_tests.yar --file test_files/test_elf32.bin

node tests/direct_compare/node_yara_runner.js --rulefile rules/test_multi_for.yar --file test_files/test_pe32.exe