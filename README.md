# gdbfuzzer
Experimental customizable deterministic fuzzer for blackbox testing binaries that take input from stdin.
Written from scratch in Python 3 to be used in CTF challenge.

## Usage
```
usage: gdbfuzzer.py [-h] -s S [-d] -g G -t T -p P

optional arguments:
  -h, --help  show this help message and exit
  -s S        Status directory.
  -d          Enable debug prints
  -g G        GDB magics template file
  -t T        Run timeout
  -p P        Fuzzed program
```

Example use:
```
mkdir gdbfuzzer_status
cat > gdbfuzzer_status/000000.json << EOF
{
    "breakpoints": [
        "0x40123b",
        "0x40126f",
        "0x40129e"
    ],
    "current_mod_byte": 0,
    "current_mod_index": 0,
    "expected_order": [
        "0x40123b"
    ],
    "id": 0
}
EOF
cp payload gdbfuzzer_status/000000.payload
cat > gdb_template.txt <<EOF
set pagination off
set architecture i386:x86-64
set breakpoint pending on

b __libc_start_main
command

b *0x004015a4
command
%BREAKPOINTS%
continue
end

continue
end
EOF

python3 gdbfuzzer.py -s gdbfuzzer_status -g gdb_template.txt -t 10 -p ./vm
```
