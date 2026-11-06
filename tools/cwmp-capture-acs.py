#!/usr/bin/env python3
"""Scripted capture ACS: drives a CWMP CPE (simulator) through a fixed list of RPCs
and saves every message the CPE sends, to build the cwmp-codec test corpus.

Usage: tools/cwmp-capture-acs.py <bind-ip> <port> <out-dir>   (env CAPTURE_SECONDS, default 60)

The host firewall may block container -> host traffic, so run it inside the dev network:

  docker run -d --rm --name dhonomos-capture-acs --network dhonomos-dev_dhonomos --user "$(id -u):$(id -g)" \
    -e CAPTURE_SECONDS=40 -v "$PWD/tools:/tools:ro" -v "$PWD/<out-dir>:/out" \
    python:3.12-alpine python3 /tools/cwmp-capture-acs.py 0.0.0.0 7547 /out
  docker run --rm --network dhonomos-dev_dhonomos dhonomos-dev/genieacs-sim --acs-url http://dhonomos-capture-acs:7547/
  # stop the simulator container afterwards (it keeps running)
"""
import http.server
import os
import re
import sys
import time

ENV = (
    '<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/" '
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    'xmlns:cwmp="urn:dslforum-org:cwmp-1-0">'
    '<soap-env:Header><cwmp:ID soap-env:mustUnderstand="1">{id}</cwmp:ID></soap-env:Header>'
    "<soap-env:Body>{body}</soap-env:Body></soap-env:Envelope>"
)


def names(paths):
    items = "".join(f"<string>{p}</string>" for p in paths)
    return f'<ParameterNames soap-enc:arrayType="xsd:string[{len(paths)}]">{items}</ParameterNames>'


def rpcs(root):
    return [
        ("GetRPCMethods", "<cwmp:GetRPCMethods/>"),
        ("GetParameterNames", f"<cwmp:GetParameterNames><ParameterPath>{root}DeviceInfo.</ParameterPath><NextLevel>true</NextLevel></cwmp:GetParameterNames>"),
        ("GetParameterValues", f"<cwmp:GetParameterValues>{names([root + 'DeviceInfo.SoftwareVersion', root + 'ManagementServer.PeriodicInformInterval'])}</cwmp:GetParameterValues>"),
        ("SetParameterValues",
         "<cwmp:SetParameterValues><ParameterList soap-enc:arrayType=\"cwmp:ParameterValueStruct[1]\">"
         f"<ParameterValueStruct><Name>{root}ManagementServer.PeriodicInformInterval</Name>"
         '<Value xsi:type="xsd:unsignedInt">600</Value></ParameterValueStruct></ParameterList>'
         "<ParameterKey>capture-1</ParameterKey></cwmp:SetParameterValues>"),
        ("GetParameterAttributes", f"<cwmp:GetParameterAttributes>{names([root + 'DeviceInfo.SoftwareVersion'])}</cwmp:GetParameterAttributes>"),
        ("SetParameterAttributes",
         "<cwmp:SetParameterAttributes><ParameterList soap-enc:arrayType=\"cwmp:SetParameterAttributesStruct[1]\">"
         f"<SetParameterAttributesStruct><Name>{root}DeviceInfo.SoftwareVersion</Name>"
         "<NotificationChange>true</NotificationChange><Notification>2</Notification>"
         "<AccessListChange>false</AccessListChange>"
         '<AccessList soap-enc:arrayType="xsd:string[0]"></AccessList>'
         "</SetParameterAttributesStruct></ParameterList></cwmp:SetParameterAttributes>"),
        ("AddObject", f"<cwmp:AddObject><ObjectName>{root}LANDevice.1.WLANConfiguration.</ObjectName><ParameterKey>capture-2</ParameterKey></cwmp:AddObject>"),
        ("DeleteObject", f"<cwmp:DeleteObject><ObjectName>{root}LANDevice.1.WLANConfiguration.99.</ObjectName><ParameterKey>capture-3</ParameterKey></cwmp:DeleteObject>"),
        ("Download",
         "<cwmp:Download><CommandKey>capture-dl</CommandKey><FileType>1 Firmware Upgrade Image</FileType>"
         "<URL>http://127.0.0.1:1/fw.bin</URL><Username></Username><Password></Password>"
         "<FileSize>0</FileSize><TargetFileName></TargetFileName><DelaySeconds>0</DelaySeconds>"
         "<SuccessURL></SuccessURL><FailureURL></FailureURL></cwmp:Download>"),
        ("FactoryReset", "<cwmp:FactoryReset/>"),
        ("Reboot", "<cwmp:Reboot><CommandKey>capture-reboot</CommandKey></cwmp:Reboot>"),
        # Last: some simulators drop the session on unknown or partial paths.
        ("GetParameterValuesFault", f"<cwmp:GetParameterValues>{names([root + 'NoSuchObject.NoSuchParam'])}</cwmp:GetParameterValues>"),
    ]


class State:
    seq = 0
    queue = None
    pending = None


def method_of(body):
    m = re.search(rb"<soap-env:Body>\s*<(?:[\w-]+:)?(\w+)", body) or re.search(rb"Body[^>]*>\s*<(?:[\w-]+:)?(\w+)", body)
    return m.group(1).decode() if m else "Empty"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[acs] " + fmt % args + "\n")

    def save(self, body, label):
        State.seq += 1
        path = os.path.join(OUT, f"{State.seq:02d}-{label}.xml")
        with open(path, "wb") as f:
            f.write(body)
        sys.stderr.write(f"[acs] saved {path}\n")

    def reply(self, xml):
        data = xml.encode()
        self.send_response(200)
        self.send_header("Content-Type", 'text/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def empty(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if body.strip():
            method = method_of(body)
            label = method if method != "Fault" else f"Fault-{State.pending}"
            if method.endswith("Response") and State.pending:
                label = f"{State.pending}Response" if not State.pending.endswith("Fault") else label
            self.save(body, label)
            if method == "Inform":
                cwmp_id = re.search(rb"<(?:\w+:)?ID[^>]*>([^<]*)<", body)
                root = "Device." if b"<Name>Device." in body else "InternetGatewayDevice."
                if State.queue is None:
                    State.queue = rpcs(root)
                return self.reply(ENV.format(id=cwmp_id.group(1).decode() if cwmp_id else "1",
                                             body='<cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse>'))
            if method == "TransferComplete":
                return self.reply(ENV.format(id="tc", body="<cwmp:TransferCompleteResponse/>"))
        else:
            self.save(b"", "Empty") if False else None
        if State.queue:
            name, rpc = State.queue.pop(0)
            State.pending = name
            self.save(ENV.format(id=f"acs-{State.seq}", body=rpc).encode(), f"ACS-{name}")
            return self.reply(ENV.format(id=f"acs-{State.seq}", body=rpc))
        State.pending = None
        return self.empty()


if __name__ == "__main__":
    bind, port, OUT = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    os.makedirs(OUT, exist_ok=True)
    srv = http.server.ThreadingHTTPServer((bind, port), Handler)
    deadline = time.time() + float(os.environ.get("CAPTURE_SECONDS", "60"))
    srv.timeout = 1
    while time.time() < deadline:
        srv.handle_request()
