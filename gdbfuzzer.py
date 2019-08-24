"""
Customizable deterministic fuzzer for blackbox testing binaries that take input from stdin.
Experimental, use at your own risk.

https://github.com/mkorkalo/gdbfuzzer
"""


import argparse
from typing import List, Optional, Tuple
import logging
import json
import glob
import os
import subprocess
import hashlib
import copy
from io import StringIO

class Status:
    def __init__(self):
        self.id: int = 0
        self.breakpoints: List[str] = []
        self.expected_order: List[str] = []
        self.current_mod_index: int = 0
        self.current_mod_byte: int = 0
        self.payload: Optional[bytes] = None

    def _read_dict(self, data: dict):
        for k, v in data.items():
            setattr(self, k, v)

    def _to_dict(self) -> dict:
        d = copy.copy(self.__dict__)

        delete = []
        for k in d:
            if k.startswith("_") or callable(getattr(self, k)):
                delete.append(k)

        for k in delete:
            del d[k]
        return d

    @staticmethod
    def payload_path(path: str) -> str:
        dir = os.path.dirname(path)
        bn = str(os.path.basename(path)).split(".")[0]
        return os.path.join(dir, bn + ".payload")

    @staticmethod
    def read(path: str) -> 'Status':
        with open(path, "r") as f:
            data = json.load(f)

        status = Status()
        status._read_dict(data)
        payload_path = Status.payload_path(path)

        with open(payload_path, "rb") as f:
            status.payload = f.read()

        return status

    def save(self, path: str, save_payload: bool):
        with open(path, "w") as f:
            d = self._to_dict()
            del d["payload"]
            json.dump(d, f, sort_keys=True, indent=4)

        if save_payload:
            payload_path = Status.payload_path(path)
            with open(payload_path, "wb") as f:
                f.write(self.payload)

class FuzzerException(Exception):
    pass


class FuzzerWrongDirectionError(FuzzerException):
    pass


class FuzzerNothingToDoError(FuzzerException):
    pass


class FuzzerNoMoreModificationsPossibleError(FuzzerException):
    pass


class PayloadFuzzer:

    def __init__(self, payload: bytes, current_mod_index: int, current_mod_byte: int):
        self.log = logging.getLogger()
        self.payload = payload
        self.current_mod_index = current_mod_index
        self.current_mod_byte: int = current_mod_byte

    def __iter__(self):
        return self

    def __next__(self) -> bytearray:
        if self.current_mod_index == len(self.payload) and self.current_mod_byte == 255:
            raise StopIteration

        if self.current_mod_byte < 255:
            self.current_mod_byte += 1
        else:
            self.current_mod_byte = 0
            self.current_mod_index += 1

        new_payload = bytearray(self.payload)
        new_payload[self.current_mod_index] = self.current_mod_byte
        return new_payload


class GdbFuzzer:

    def __init__(self):
        self.log = logging.getLogger()
        self.status_dir: Optional[str] = None
        self.gdb_magics: Optional[str] = None
        self.fuzzed_program: Optional[str] = None
        self.timeout: int = 10

    def read_status(self) -> Status:
        last = None
        for fn in reversed(sorted(glob.glob(os.path.join(self.status_dir, "*.json")))):
            last = fn
            break
        if not last:
            raise Exception(f"Create a file in {self.status_dir} with contents for first status")

        status = Status.read(last)

        return status

    def breakpoint_hash(self, breakpoint: str) -> str:
        return hashlib.sha1(breakpoint.encode()).digest()[0:6].hex()

    def create_gdb_script(self, tmp_file: str) -> (str, List[str]):
        with open(self.gdb_magics, "r") as f:
            template = f.read()

        breakpoints = []
        expected_order = []
        script = ""

        # Generate traces from all breakpoints
        for fn in glob.glob(os.path.join(self.status_dir, "*.json")):
            status = Status.read(fn)
            for b in status.breakpoints:
                breakpoints.append(b)
                short_hash = self.breakpoint_hash(b)
                script += f'b *{b}\n' \
                       'command\n' \
                       'silent\n' \
                       f'print "{short_hash}: 0x{b}"\n' \
                       'x/x $rdx\n' \
                       'cont\n' \
                       'end\n'

            for b in status.expected_order:
                expected_order.append(b)

        final_script = template.replace("%BREAKPOINTS%", script)

        final_script += f"\nr < {tmp_file}\n"

        return final_script, expected_order

    def _write_gdb_magic(self, pipe: subprocess.PIPE):
        pass

    def run_with_gdb(self, fuzzed_payload: bytes):
        tmp_file = "payload_fuzz.tmp"
        with open(tmp_file, "wb") as f:
            f.write(fuzzed_payload)

        script, order = self.create_gdb_script(tmp_file)
        #self.log.debug("script: %s", script)

        output = subprocess.check_output(["gdb", self.fuzzed_program],
                                         stderr=subprocess.STDOUT,
                                         input=script.encode(),
                                         timeout=10
                                         ).decode()
        self.log.debug("gdb output: %s", output)
        seen_breakpoints: List[Tuple[str, str, int]] = []
        reader = StringIO(output)

        for line_n, line in enumerate(reader):
            for bpoint in order:
                hash = self.breakpoint_hash(bpoint)
                if hash in line:
                    seen_breakpoints.append((hash, bpoint, line_n,))
                    # We assume no other breakpoints in the same line
        self.log.info("seen breakpoints: %s", seen_breakpoints)
        self.log.info("expected breakpoints: %s", order)

        for breakpoint_n, bpoint in enumerate(order):
            hash = self.breakpoint_hash(bpoint)
            try:
                got_hash, got_bpoint, line_n = seen_breakpoints.pop(0)
            except IndexError:
                self.log.info("Cannot see breakpoint %s", bpoint)
                raise FuzzerWrongDirectionError()
            if got_hash != hash:
                self.log.info("Got breakpoint %s instead of %s, failing", got_bpoint, bpoint)
                raise FuzzerWrongDirectionError()

            self.log.info("Found breakpoint %s (#%s hash %s) in gdb output line number %s: %s",
                          bpoint, breakpoint_n, hash, line_n, got_bpoint)

    def _fuzz_loop(self, fuzzer: PayloadFuzzer, status: Status):
        for fuzzed_payload in fuzzer:
            if len(status.expected_order) < 1:
                raise FuzzerNothingToDoError()
            self.log.info("Fuzzing byte #%04x to %02x...", fuzzer.current_mod_index, fuzzer.current_mod_byte)
            status.current_mod_index = fuzzer.current_mod_index
            status.current_mod_byte = fuzzer.current_mod_byte
            if status.current_mod_byte % 10 == 0:
                status.save(os.path.join(self.status_dir, str(status.id).zfill(6) + ".json"), save_payload=False)

            try:
                self.run_with_gdb(fuzzed_payload)
            except FuzzerWrongDirectionError as e:
                self.log.debug("we're going to the wrong direction, try something else: %s", e)
                continue
            except TimeoutError:
                self.log.debug("timeout")
                continue

            self.log.info("Woo-hoo! We advanced in fuzzing. Saving status.")
            new_status = copy.deepcopy(status)
            new_status.id = status.id + 1
            try:
                new_status.expected_order.pop(0)
            except IndexError:
                pass
            new_status.breakpoints = []
            new_status.save(os.path.join(self.status_dir, str(new_status.id).zfill(6) + ".json"), save_payload=True)
            return
        raise FuzzerNoMoreModificationsPossibleError("We can only modify a single byte from "
                                                     "payload and every possible modification was done.")

    def run(self):
        while True:
            status = self.read_status()
            if len(status.expected_order) < 1:
                raise FuzzerNothingToDoError("Add more breakpoints in expected_order or be happy with the results")
            fuzzer = PayloadFuzzer(status.payload, status.current_mod_index, status.current_mod_byte)
            self._fuzz_loop(fuzzer, status)


def line_filter(x: str):
    return not x or x.startswith("#")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", type=str, help="Status directory.", required=True)
    parser.add_argument("-d", help="Enable debug prints", action="store_true")
    parser.add_argument("-g", help="GDB magics template file", required=True)
    parser.add_argument("-t", help="Run timeout", type=int, default=10, required=True)
    parser.add_argument("-p", help="Fuzzed program", type=str, required=True)

    args = parser.parse_args()
    if args.d:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig()
    log = logging.getLogger()
    log.setLevel(level)

    fuzzer = GdbFuzzer()
    fuzzer.status_dir = args.s
    fuzzer.gdb_magics = args.g
    fuzzer.command_timeout = args.t
    fuzzer.fuzzed_program = args.p
    fuzzer.timeout = args.t
    fuzzer.run()


if __name__ == '__main__':
    main()
