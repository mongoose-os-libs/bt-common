#!/usr/bin/env python3
#
# Copyright (c) 2021 Deomid "rojer" Ryabkov
# All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import binascii
import logging
import json
import random
import struct
import time
import sys

from bluepy import btle


class ScanDelegate(btle.DefaultDelegate):

    def handleDiscovery(self, data, isNewDev, isNewData):
        if data.updateCount > 1:
            return
        name = data.getValueText(9)  # Complete Local Name
        if not name:
            name = data.getValueText(8)  # Shortened Local Name
        if not name:
            name = '?'
        print(data.addr, data.rssi, name)


class ResolveDelegate(btle.DefaultDelegate):
    _name: str
    _addr: str
    _addrType: int
    _scanner: btle.Scanner

    def __init__(self, name: str):
        super().__init__()
        self._name = name
        self._addr = None
        self._addrType = 0
        self._scanner = None

    def handleDiscovery(self, data, isNewDev, isNewData):
        name = data.getValueText(9)  # Complete Local Name
        if not name:
            name = data.getValueText(8)  # Shortened Local Name
        logging.debug(f"{data.addr} {data.rssi} {name}")
        if name == self._name:
            self._addr = data.addr
            self._addrType = data.addrType

    def getAddr(self):
        return (self._addr, self._addrType)


class Device(btle.Peripheral):

    def __init__(self, addr, addrType):
        super().__init__(addr, addrType=btle.ADDR_TYPE_PUBLIC)
        # See https://github.com/mongoose-os-libs/rpc-gatts#attribute-description
        svc = self.getServiceByUUID("5f6d4f53-5f52-5043-5f53-56435f49445f")
        self._data_char, self._tx_ctl_char, self._rx_ctl_char = None, None, None
        for char in svc.getCharacteristics():
            if char.uuid == "5f6d4f53-5f52-5043-5f64-6174615f5f5f":
                self._data_char = char
            elif char.uuid == "5f6d4f53-5f52-5043-5f74-785f63746c5f":
                self._tx_ctl_char = char
            elif char.uuid == "5f6d4f53-5f52-5043-5f72-785f63746c5f":
                self._rx_ctl_char = char
        if not (self._data_char and self._tx_ctl_char and self._rx_ctl_char):
            raise TypeError("invalid service")

    def call(self, method, params=None, resp=True):
        req = {
            "method": method,
            "params": params or {},
        }
        if resp:
            req["id"] = random.randint(1, 1000000000)
        reqJSON = json.dumps(req)
        reqLen = len(reqJSON)
        logging.debug(f"Request: {reqJSON}")
        logging.debug(f"Writing length ({reqLen})...")
        self._tx_ctl_char.write(struct.pack(">I", reqLen), withResponse=True)
        logging.debug(f"Sending request...")
        self._data_char.write(reqJSON.encode("ascii"), withResponse=True)
        while True:
            frame_len = struct.unpack(">I", self._rx_ctl_char.read())[0]
            logging.debug(f"RX frame len: {frame_len}")
            if frame_len == 0:
                time.sleep(0.1)
                continue
            frame_data, n_chunks = b"", 0
            while len(frame_data) < frame_len:
                chunk = self._data_char.read()
                frame_data += chunk
                n_chunks += 1
            logging.debug(f"RX Frame data (rec'd in {n_chunks} chunks): {frame_data}")
            frame = json.loads(frame_data)
            if frame.get("id", 0) != req["id"]:
                continue
            if "result" in frame:
                print(json.dumps(frame["result"]).encode("ascii"))
                sys.exit(0)
            elif "error" in frame:
                print(json.dumps(frame["error"]).encode("ascii"))
                sys.exit(2)
            else:
                logging.error(f"Invalid frame: {frame}")
                sys.exit(1)

    def unlock(self):
        self.writeCharacteristic(0x0047, bytes([0, 0, 0, 0]))
        v3d = self.readCharacteristic(0x003d)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--v", type=int, default=logging.INFO, help="Verbosity level")
    sp = parser.add_subparsers(title="Actions", dest="action", required=True)
    # scan
    scan_parser = sp.add_parser("scan", help="Scan for devices")
    scan_parser.add_argument("-t", "--time", type=float, default=10.0, help="Scan for this long")
    # call
    call_parser = sp.add_parser("call", help="Invoke an RPC method")
    call_parser.add_argument("--addr_type", type=str, default="public", help="Address type, public or random")
    call_parser.add_argument("target", action="store", help="Name or MAC address of the device")
    call_parser.add_argument("method", action="store", help="Method to invoke")
    call_parser.add_argument("params", action="store", nargs="?", help="Call parameters, JSON object")
    args = parser.parse_args()

    logging.basicConfig(level=args.v, format="[%(asctime)s %(levelno)d] %(message)s", datefmt="%Y/%m/%d %H:%M:%S")

    if args.action == "scan":
        sd = ScanDelegate()
        scanner = btle.Scanner().withDelegate(sd)
        devices = scanner.scan(args.time)
        return
    elif args.action == "call":
        params = {}
        if args.params is not None:
            params = json.loads(args.params)
        addrType = args.addr_type
        if len(args.target.split(":")) == 6:
            addr = args.target
        elif len(args.target.split("-")) == 6:
            addr = ":".join(args.target.split("-"))
        else:
            logging.info(f"Resolving {args.target}...")
            rd = ResolveDelegate(args.target)
            scanner = btle.Scanner().withDelegate(rd)
            scanner.clear()
            scanner.start()
            start = time.time()
            while not rd.getAddr()[0] and time.time() - start < 5:
                scanner.process(timeout=0.5)
            scanner.stop()
            addr, addrType = rd.getAddr()
            if not addr:
                logging.error(f"Could not resolve {args.target}")
                sys.exit(1)
        logging.info(f"Connecting to {addr}...")
        dev = None
        try:
            dev = Device(addr, addrType)
            dev.call(args.method, params=params, resp=True)
        finally:
            if dev:
                dev.disconnect()

if __name__ == "__main__":
    main()
