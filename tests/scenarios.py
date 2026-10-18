"""Synthetic capture scenarios for the OTscope regression suite.

Each builder returns a pcapgen.Net, or a {file name: Net} dict for scenarios
that span several capture files.  "benign_*" scenarios model ordinary
plant / office traffic and must not produce intrusion-class findings;
"attack_*" scenarios contain the behavior a detector is meant to catch.
"""

from __future__ import annotations

import struct
from typing import Dict

from pcapgen import (
    WSD_HELLO,
    Net,
    dnp3_frame,
    iec104_i_frame,
    modbus_coils_response,
    modbus_read_response,
    modbus_request,
    modbus_write_multiple,
    modbus_write_multiple_response,
    modbus_write_single,
    mqtt_connect,
    mqtt_publish,
    rtp_packet,
    sdp_body,
    snmp_message,
    tls_hello_pair,
)


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"


def _dns_query(qid: int, name: str) -> bytes:
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack(">HH", 1, 1)


def _dns_answer(qid: int, name: str, ip: str) -> bytes:
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes(int(p) for p in ip.split("."))
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + _dns_name(name) + struct.pack(">HH", 1, 1) + answer


def benign_modbus_hmi() -> Net:
    """HMI polls two PLCs (1 s single block with delayed ACKs; 2 s three-function
    scan group), makes one setpoint write, and syncs NTP every 64 s."""
    n = Net(seed=11)
    hmi, plc1, plc2, ntp = "10.10.1.10", "10.10.1.20", "10.10.1.21", "10.10.1.1"
    t0 = n.t0
    s1 = n.session(hmi, 49733, plc1, 502).open(t0)
    for cyc in range(300):
        tid = cyc + 1
        ct = t0 + 0.5 + cyc * 1.0 + n.rng.uniform(-0.004, 0.004)
        if cyc == 150:
            s1.c2s(modbus_write_single(tid, 5, 1200), ct)
            s1.s2c(modbus_write_single(tid, 5, 1200), ct + 0.012)
        else:
            s1.c2s(modbus_request(tid, 3, 0, 10), ct)
            s1.s2c(modbus_read_response(tid, 3, [1000 + n.rng.randint(0, 5) for _ in range(10)]), ct + 0.012)
        s1.ack_c(ct + 0.2)
    s2 = n.session(hmi, 49741, plc2, 502).open(t0 + 0.2)
    tid2 = 0
    for cyc in range(500):
        ct = t0 + 1.0 + cyc * 2.0 + n.rng.uniform(-0.003, 0.003)
        for k, fc in enumerate((3, 4, 1)):
            tid2 += 1
            st = ct + k * 0.03
            s2.c2s(modbus_request(tid2, fc, 100 * k, 8), st)
            if fc == 1:
                s2.s2c(modbus_coils_response(tid2, 8), st + 0.01)
            else:
                s2.s2c(modbus_read_response(tid2, fc, [2000 + k] * 8), st + 0.01)
    for i in range(17):
        nt = t0 + 5 + i * 64.0 + n.rng.uniform(-0.01, 0.01)
        n.udp(nt, hmi, 123, ntp, 123, b"\x23" + bytes(47))
        n.udp(nt + 0.002, ntp, 123, hmi, 123, b"\x24\x02" + bytes(46))
    return n


def benign_scada_master() -> Net:
    """One SCADA master polling a Modbus PLC, a DNP3 outstation, and an IEC-104 RTU,
    including the routine IEC-104 General Interrogation and one operator command."""
    n = Net(seed=12)
    master, plc, outstation, rtu = "10.20.0.5", "10.20.0.10", "10.20.0.11", "10.20.0.12"
    t0 = n.t0
    sm = n.session(master, 50001, plc, 502).open(t0)
    for i in range(10):
        t = t0 + 1 + i * 5
        sm.c2s(modbus_request(i + 1, 3, 0, 4), t)
        sm.s2c(modbus_read_response(i + 1, 3, [10, 20, 30, 40]), t + 0.01)
        sm.ack_c(t + 0.2)
    sd = n.session(master, 50002, outstation, 20000).open(t0 + 0.1)
    for i in range(10):
        t = t0 + 2 + i * 5
        req = bytes([0xC0 | (i & 0x3F), 0xC0 | (i & 0x0F), 0x01, 0x3C, 0x01, 0x06])
        rsp = bytes([0xC0 | (i & 0x3F), 0xC0 | (i & 0x0F), 0x81, 0x00, 0x00])
        sd.c2s(dnp3_frame(10, 1, 0xC4, req), t)
        sd.s2c(dnp3_frame(1, 10, 0x44, rsp), t + 0.02)
        sd.ack_c(t + 0.2)
    si = n.session(master, 50003, rtu, 2404).open(t0 + 0.2)
    si.c2s(bytes.fromhex("680407000000"), t0 + 0.3)
    si.s2c(bytes.fromhex("68040B000000"), t0 + 0.31)
    si.c2s(iec104_i_frame(0, 0, bytes.fromhex("64010600010000000014")), t0 + 0.4)
    si.s2c(iec104_i_frame(0, 1, bytes.fromhex("64010700010000000014")), t0 + 0.41)
    si.c2s(iec104_i_frame(1, 1, bytes.fromhex("2D010600010001000001")), t0 + 30)
    si.s2c(iec104_i_frame(1, 2, bytes.fromhex("2D010700010001000001")), t0 + 30.02)
    return n


def benign_office_lan() -> Net:
    """Plain office LAN with no OT: a Windows PC serving SMB, announcing itself
    via WS-Discovery, polling a printer over SNMP, and resolving names."""
    n = Net(seed=13)
    pc, peer, printer, dns = "10.30.0.50", "10.30.0.51", "10.30.0.60", "10.30.0.1"
    t0 = n.t0
    smb = n.session(peer, 51000, pc, 445).open(t0)
    for i in range(6):
        smb.c2s(b"\x00\x00\x00\x40\xfeSMB" + bytes(60), t0 + 1 + i)
        smb.s2c(b"\x00\x00\x00\x40\xfeSMB" + bytes(60), t0 + 1.01 + i)
    for i in range(25):
        n.udp(t0 + 2 + i * 7.3, pc, 3702, "239.255.255.250", 3702, WSD_HELLO)
    for i in range(10):
        t = t0 + 3 + i * 30
        n.udp(t, pc, 55001, printer, 161, snmp_message("public", 0xA0, i + 1, "1.3.6.1.2.1.43.11.1.1.9.1.1"))
        n.udp(t + 0.003, printer, 161, pc, 55001, snmp_message("public", 0xA2, i + 1, "1.3.6.1.2.1.43.11.1.1.9.1.1", 4200))
    for i in range(5):
        t = t0 + 4 + i * 20
        n.udp(t, pc, 53000 + i, dns, 53, _dns_query(100 + i, "fileserver.corp.local"))
        n.udp(t + 0.002, dns, 53, pc, 53000 + i, _dns_answer(100 + i, "fileserver.corp.local", "10.30.0.5"))
    return n


def windows_hmi_dual_zone() -> Net:
    """A Windows HMI that polls a PLC and also serves SMB/RDP to an office workstation."""
    n = Net(seed=14)
    hmi, plc, office = "10.90.1.10", "10.90.1.20", "10.90.2.50"
    t0 = n.t0
    s = n.session(hmi, 50100, plc, 502).open(t0)
    for i in range(20):
        t = t0 + 1 + i * 2
        s.c2s(modbus_request(i + 1, 3, 0, 4), t)
        s.s2c(modbus_read_response(i + 1, 3, [1, 2, 3, 4]), t + 0.01)
        s.ack_c(t + 0.2)
    rdp = n.session(office, 52000, hmi, 3389).open(t0 + 3)
    for i in range(10):
        rdp.c2s(b"\x03\x00\x00\x13" + bytes(15), t0 + 4 + i)
        rdp.s2c(b"\x03\x00\x00\x13" + bytes(15), t0 + 4.01 + i)
    smb = n.session(office, 52001, hmi, 445).open(t0 + 20)
    smb.c2s(b"\x00\x00\x00\x40\xfeSMB" + bytes(60), t0 + 21)
    smb.s2c(b"\x00\x00\x00\x40\xfeSMB" + bytes(60), t0 + 21.01)
    return n


def attack_creds_bruteforce() -> Net:
    """Cleartext logins on FTP, HTTP (Basic + form), Telnet, MQTT and SNMP, an
    anonymous MQTT client, FTP/HTTP/Telnet password guessing from 10.40.0.99,
    and a TLS 1.0 session negotiating RC4."""
    n = Net(seed=15)
    hmi, plc, attacker, mqtt_client, anon_client, broker = (
        "10.40.0.10", "10.40.0.20", "10.40.0.99", "10.40.0.30", "10.40.0.31", "10.40.0.40")
    t0 = n.t0
    mbs = n.session(hmi, 50010, plc, 502).open(t0)
    for i in range(5):
        mbs.c2s(modbus_request(i + 1, 3, 0, 2), t0 + 1 + i)
        mbs.s2c(modbus_read_response(i + 1, 3, [1, 2]), t0 + 1.01 + i)
    ftp = n.session(hmi, 50100, plc, 21).open(t0 + 10)
    ftp.s2c(b"220 PLC FTP server ready\r\n", t0 + 10.01)
    ftp.c2s(b"USER admin\r\n", t0 + 10.5)
    ftp.s2c(b"331 Password required for admin\r\n", t0 + 10.51)
    ftp.c2s(b"PASS hunter2\r\n", t0 + 11.0)
    ftp.s2c(b"230 User admin logged in\r\n", t0 + 11.01)
    for i in range(12):
        t = t0 + 20 + i * 2
        bf = n.session(attacker, 41000 + i, plc, 21).open(t)
        bf.s2c(b"220 PLC FTP server ready\r\n", t + 0.01)
        bf.c2s(b"USER admin\r\n", t + 0.1)
        bf.s2c(b"331 Password required for admin\r\n", t + 0.11)
        bf.c2s(("PASS guess%d\r\n" % i).encode(), t + 0.2)
        bf.s2c(b"530 Login incorrect.\r\n", t + 0.21)
        bf.close(t + 0.3)
    web = n.session(hmi, 50200, plc, 80).open(t0 + 60)
    web.c2s(b"GET /config HTTP/1.1\r\nHost: 10.40.0.20\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n", t0 + 60.1)
    web.s2c(b"HTTP/1.1 200 OK\r\nServer: Boa/0.94.13\r\nContent-Length: 2\r\n\r\nok", t0 + 60.11)
    form = b"username=operator&password=Passw0rd!"
    web.c2s(b"POST /login HTTP/1.1\r\nHost: 10.40.0.20\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form, t0 + 61)
    web.s2c(b"HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n", t0 + 61.01)
    for i in range(12):
        t = t0 + 70 + i * 2
        hb = n.session(attacker, 42000 + i, plc, 80).open(t)
        hb.c2s(b"GET /config HTTP/1.1\r\nHost: 10.40.0.20\r\nAuthorization: Basic YWRtaW46d3Jvbmc=\r\n\r\n", t + 0.1)
        hb.s2c(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"plc\"\r\nContent-Length: 0\r\n\r\n", t + 0.11)
        hb.close(t + 0.2)
    tn = n.session(hmi, 50300, plc, 23).open(t0 + 100)
    tn.s2c(b"\r\nPLC-01 login: ", t0 + 100.1)
    tn.c2s(b"operator\r\n", t0 + 100.5)
    tn.s2c(b"Password: ", t0 + 100.6)
    tn.c2s(b"Telnet123\r\n", t0 + 101)
    tn.s2c(b"\r\nWelcome to PLC-01\r\n$ ", t0 + 101.1)
    for i in range(12):
        t = t0 + 140 + i * 2
        tb = n.session(attacker, 43000 + i, plc, 23).open(t)
        tb.s2c(b"\r\nPLC-01 login: ", t + 0.05)
        tb.c2s(b"admin\r\n", t + 0.1)
        tb.s2c(b"Password: ", t + 0.15)
        tb.c2s(("guess%d\r\n" % i).encode(), t + 0.2)
        tb.s2c(b"\r\nLogin incorrect\r\n", t + 0.25)
        tb.close(t + 0.3)
    mq = n.session(mqtt_client, 50400, broker, 1883).open(t0 + 110)
    mq.c2s(mqtt_connect("plc-gw-01", "sensor01", "mqttpass"), t0 + 110.1)
    mq.s2c(b"\x20\x02\x00\x00", t0 + 110.11)
    mq.c2s(mqtt_publish("plant/line1/temp", b"21.5"), t0 + 111)
    anon = n.session(anon_client, 50401, broker, 1883).open(t0 + 112)
    anon.c2s(mqtt_connect("anon-01"), t0 + 112.1)
    anon.s2c(b"\x20\x02\x00\x00", t0 + 112.11)
    for i in range(3):
        t = t0 + 120 + i
        n.udp(t, hmi, 55100, plc, 161, snmp_message("plantRW", 0xA0, i + 1, "1.3.6.1.2.1.1.1.0"))
        n.udp(t + 0.002, plc, 161, hmi, 55100, snmp_message("plantRW", 0xA2, i + 1, "1.3.6.1.2.1.1.1.0", 1))
    hello, server_hello = tls_hello_pair(0x0301, [0x0005, 0x000A], 0x0005)
    tls = n.session(hmi, 50500, plc, 443).open(t0 + 130)
    tls.c2s(hello, t0 + 130.1)
    tls.s2c(server_hello, t0 + 130.11)
    return n


def attack_modbus_recon_injection() -> Net:
    """Normal HMI polling plus an attacker that sweeps hosts with ICMP, probes OT
    ports, scans the PLC's register map, writes to it, and replays responses."""
    n = Net(seed=16)
    hmi, plc, attacker = "10.70.0.10", "10.70.0.20", "10.70.0.66"
    t0 = n.t0
    s = n.session(hmi, 50010, plc, 502).open(t0)
    for cyc in range(60):
        tid = cyc + 1
        ct = t0 + 1 + cyc * 1.0
        s.c2s(modbus_request(tid, 3, 0, 10), ct)
        resp = modbus_read_response(tid, 3, [1000] * 10)
        s.s2c(resp, ct + 0.01)
        s.ack_c(ct + 0.2)
        if cyc in (20, 25, 30, 35, 40):
            s.s2c(resp, ct + 0.3)  # injected second answer to the same transaction
            s.ack_c(ct + 0.4)
    for i in range(30):
        n.icmp_echo(t0 + 70 + i * 0.05, attacker, "10.70.0.%d" % (i + 1), 0x4242, i)
    for host in range(20, 26):
        for port_idx, port in enumerate((502, 20000, 2404, 44818, 102)):
            if host == 20 and port == 502:
                continue
            n.session(attacker, 40000 + host * 10 + port_idx, "10.70.0.%d" % host, port).refused(
                t0 + 80 + host * 0.2 + port_idx * 0.01)
    scan = n.session(attacker, 45000, plc, 502).open(t0 + 90)
    for i in range(100):
        tid = 1000 + i
        t = t0 + 91 + i * 0.05
        scan.c2s(modbus_request(tid, 3, i * 10, 10), t)
        scan.s2c(modbus_read_response(tid, 3, [i] * 10), t + 0.005)
    scan.c2s(modbus_write_multiple(2000, 40, [9999, 9999]), t0 + 100)
    scan.s2c(modbus_write_multiple_response(2000, 40, 2), t0 + 100.01)
    return n


def attack_arp_mitm() -> Net:
    """An attacker poisons ARP for the PLC (sender MAC differs from the Ethernet
    source) while the HMI keeps writing to the PLC."""
    n = Net(seed=17)
    hmi, plc = "10.80.0.10", "10.80.0.20"
    attacker_mac = "00:0c:29:aa:bb:cc"
    t0 = n.t0
    n.arp(t0, 2, n.mac(plc), plc, hmi, target_mac=n.mac(hmi), eth_dst=n.mac(hmi))
    for i in range(12):
        n.arp(t0 + 1 + i * 0.5, 2, attacker_mac, plc, hmi, target_mac=n.mac(hmi),
              eth_src="00:0c:29:11:22:33", eth_dst=n.mac(hmi))
    s = n.session(hmi, 50020, plc, 502).open(t0 + 2)
    for i in range(10):
        t = t0 + 3 + i
        s.c2s(modbus_write_single(i + 1, 7, 100 + i), t)
        s.s2c(modbus_write_single(i + 1, 7, 100 + i), t + 0.01)
    return n


def av_camera_voip() -> Net:
    """A VMS pulls one password-protected and one unprotected RTSP camera stream;
    an IP phone places a SIP call with G.711 RTP media."""
    n = Net(seed=18)
    cam1, cam2, vms, phone, pbx = "10.50.0.10", "10.50.0.11", "10.50.0.20", "10.50.0.30", "10.50.0.40"
    t0 = n.t0
    url1 = b"rtsp://10.50.0.10:554/Streaming/Channels/101"
    r1 = n.session(vms, 50600, cam1, 554).open(t0)
    exchange = [
        (b"OPTIONS " + url1 + b" RTSP/1.0\r\nCSeq: 1\r\n\r\n", b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n"),
        (b"DESCRIBE " + url1 + b" RTSP/1.0\r\nCSeq: 2\r\n\r\n",
         b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nWWW-Authenticate: Digest realm=\"cam\", nonce=\"abc\"\r\n\r\n"),
        (b"DESCRIBE " + url1 + b" RTSP/1.0\r\nCSeq: 3\r\nAuthorization: Digest username=\"vms\", realm=\"cam\", nonce=\"abc\", uri=\"x\", response=\"0\"\r\n\r\n",
         b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nContent-Type: application/sdp\r\nContent-Length: 0\r\n\r\n"),
        (b"SETUP " + url1 + b"/trackID=1 RTSP/1.0\r\nCSeq: 4\r\nTransport: RTP/AVP;unicast;client_port=50000-50001\r\n\r\n",
         b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 1234\r\nTransport: RTP/AVP;unicast;client_port=50000-50001;server_port=8200-8201\r\n\r\n"),
        (b"PLAY " + url1 + b" RTSP/1.0\r\nCSeq: 5\r\nSession: 1234\r\n\r\n", b"RTSP/1.0 200 OK\r\nCSeq: 5\r\nSession: 1234\r\n\r\n"),
    ]
    t = t0 + 0.1
    for request, reply in exchange:
        r1.c2s(request, t)
        r1.s2c(reply, t + 0.01)
        t += 0.2
    url2 = b"rtsp://10.50.0.11:554/live"
    r2 = n.session(vms, 50601, cam2, 554).open(t0 + 2)
    t = t0 + 2.1
    for request, reply in [
        (b"DESCRIBE " + url2 + b" RTSP/1.0\r\nCSeq: 1\r\n\r\n", b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: 0\r\n\r\n"),
        (b"SETUP " + url2 + b"/track1 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP;unicast;client_port=50010-50011\r\n\r\n",
         b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 99\r\n\r\n"),
        (b"PLAY " + url2 + b" RTSP/1.0\r\nCSeq: 3\r\nSession: 99\r\n\r\n", b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 99\r\n\r\n"),
    ]:
        r2.c2s(request, t)
        r2.s2c(reply, t + 0.01)
        t += 0.2
    sdp = sdp_body(phone, 40000)
    invite = (b"INVITE sip:200@10.50.0.40 SIP/2.0\r\nVia: SIP/2.0/UDP 10.50.0.30:5060;branch=z9hG4bK1\r\n"
              b"From: <sip:100@10.50.0.40>;tag=1\r\nTo: <sip:200@10.50.0.40>\r\nCall-ID: abc@10.50.0.30\r\n"
              b"CSeq: 1 INVITE\r\nContact: <sip:100@10.50.0.30>\r\nContent-Type: application/sdp\r\n"
              b"Content-Length: " + str(len(sdp)).encode() + b"\r\n\r\n" + sdp)
    ok = (b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.50.0.30:5060;branch=z9hG4bK1\r\nFrom: <sip:100@10.50.0.40>;tag=1\r\n"
          b"To: <sip:200@10.50.0.40>;tag=2\r\nCall-ID: abc@10.50.0.30\r\nCSeq: 1 INVITE\r\nContact: <sip:200@10.50.0.40>\r\n"
          b"Content-Type: application/sdp\r\nContent-Length: " + str(len(sdp)).encode() + b"\r\n\r\n" + sdp)
    n.udp(t0 + 5, phone, 5060, pbx, 5060, invite)
    n.udp(t0 + 5.5, pbx, 5060, phone, 5060, ok)
    for i in range(300):
        n.udp(t0 + 6 + i * 0.02, phone, 40000, pbx, 40000, rtp_packet(i, i * 160))
    return n


def s7_engineering() -> Net:
    """Engineering station opens an S7comm session to a PLC on TCP/102 and reads a variable."""
    n = Net(seed=19)
    ews, plc = "10.60.0.5", "10.60.0.10"
    t0 = n.t0
    s = n.session(ews, 50700, plc, 102).open(t0)
    s.c2s(bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102"), t0 + 0.01)
    s.s2c(bytes.fromhex("0300001611d00001000100c0010ac1020100c2020102"), t0 + 0.02)
    s.c2s(bytes.fromhex("0300001902f08032010000000000080000f0000001000101e0"), t0 + 0.03)
    s.s2c(bytes.fromhex("0300001b02f080320300000000000800000000f0000001000100f0"), t0 + 0.04)
    for i in range(5):
        s.c2s(bytes.fromhex("0300001f02f080320100000001000e00000401120a10020001000084000000"), t0 + 1 + i)
        s.s2c(bytes.fromhex("0300001b02f0803203000000010002000600000401ff04001000"), t0 + 1.01 + i)
    return n


def arp_same_ms() -> Net:
    """Forty hosts ARP for their gateway within one millisecond (e.g. after a switch reboot)."""
    n = Net(seed=20)
    for i in range(40):
        ip = "10.95.0.%d" % (i + 10)
        n.arp(n.t0 + 0.00001 * i, 1, n.mac(ip), ip, "10.95.0.1")
    for i in range(5):
        n.udp(n.t0 + 1 + i, "10.95.0.10", 47808, "10.95.0.11", 47808,
              b"\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08")
    return n


def modbus_value_jump() -> Net:
    """An HMI polls a holding-register pair once a second; one response reports
    a sudden spike in the first register (a spoofed or injected process value)."""
    n = Net(seed=21)
    hmi, plc = "10.11.0.10", "10.11.0.20"
    s = n.session(hmi, 50100, plc, 502).open(n.t0)
    for i, value in enumerate([100] * 8 + [5000] + [100] * 6):
        t = n.t0 + 1 + i
        s.c2s(modbus_request(i + 1, 3, 40, 2), t)
        s.s2c(modbus_read_response(i + 1, 3, [value, 7]), t + 0.01)
        s.ack_c(t + 0.2)
    return n


def attack_mitm_intercept() -> Net:
    """Modeled on a real one-way ARP MITM capture taken at the PLC's switch port.

    An HMI polls a PLC with transaction ID 0 and once packs 11 requests into
    one segment.  An attacker VM (own address .80) sends unsolicited ARP
    replies telling the PLC that the HMI's IP is at its MAC; for 20 s the
    HMI's traffic reaches the PLC through the attacker, then the attacker
    re-announces the real MAC.  A second client writes a register every 3 s
    with requests sent one byte per TCP segment and closes each connection
    with FIN, after which the PLC sends two RSTs.  The HMI also broadcasts
    NetBIOS and multicast mDNS.
    """
    n = Net(seed=22)
    hmi, plc, writer, attacker_ip = "10.61.0.70", "10.61.0.250", "10.61.0.251", "10.61.0.80"
    hmi_mac, attacker_mac = "00:0c:29:9d:9e:9e", "00:0c:29:e6:14:0d"
    n.set_mac(hmi, hmi_mac)
    n.set_mac(attacker_ip, attacker_mac)
    plc_mac = n.mac(plc)
    t0 = n.t0
    poll = n.session(hmi, 49499, plc, 502).open(t0)
    attack_start, attack_end = t0 + 30, t0 + 50
    t = t0 + 1
    burst_done = False
    while t < t0 + 80:
        if attack_start <= t < attack_end:
            n.set_mac(hmi, attacker_mac)
        else:
            n.set_mac(hmi, hmi_mac)
        if not burst_done and t > t0 + 60:
            poll.c2s(b"".join(modbus_request(0, 3, 0, 10) for _ in range(11)), t)
            for i in range(11):
                poll.s2c(modbus_read_response(0, 3, [1, 0, 0, 30, 0, 0, 0, 0, 0, 0]), t + 0.01 + i * 0.0004)
            burst_done = True
        else:
            poll.c2s(modbus_request(0, 3, 0, 10), t)
            poll.s2c(modbus_read_response(0, 3, [1, 0, 0, 30, 0, 0, 0, 0, 0, 0]), t + 0.01)
        poll.ack_c(t + 0.2)
        t += 0.3
    n.set_mac(hmi, hmi_mac)
    for i in range(10):
        n.arp(t0 + 2 + i * 8, 1, hmi_mac, hmi, plc, eth_dst=plc_mac)
        n.arp(t0 + 2.001 + i * 8, 2, plc_mac, plc, hmi, target_mac=hmi_mac, eth_dst=hmi_mac)
    n.arp(attack_start - 1.0, 1, attacker_mac, attacker_ip, hmi)
    n.arp(attack_start - 0.999, 2, hmi_mac, hmi, attacker_ip, target_mac=attacker_mac, eth_dst=attacker_mac)
    n.arp(attack_start - 0.99, 1, attacker_mac, attacker_ip, plc)
    n.arp(attack_start - 0.989, 2, plc_mac, plc, attacker_ip, target_mac=attacker_mac, eth_dst=attacker_mac)
    for i in range(6):
        n.arp(attack_start - 0.5 + i * 4, 2, attacker_mac, hmi, plc, target_mac=plc_mac, eth_dst=plc_mac)
    for i in range(3):
        n.arp(attack_end + 0.5 + i, 2, hmi_mac, hmi, plc, target_mac=plc_mac, eth_src=attacker_mac, eth_dst=plc_mac)
    for k in range(25):
        start = t0 + 1.5 + k * 3
        w = n.session(writer, 50100 + k, plc, 502).open(start)
        for i, byte in enumerate(modbus_write_single(1, 40, 100 + k)):
            w.c2s(bytes([byte]), start + 0.01 + i * 0.0002)
        w.s2c(modbus_write_single(1, 40, 100 + k), start + 0.02)
        w.ack_c(start + 0.2)
        w.close(start + 1.0)
        n.tcp(start + 1.001, plc, 502, writer, 50100 + k, w.sseq, w.cseq, "RA")
        n.tcp(start + 1.002, plc, 502, writer, 50100 + k, w.sseq, 0, "R")
    for i in range(8):
        n.udp(t0 + 3 + i * 9, hmi, 138, "10.61.0.255", 138, b"\x11\x0a" + b"\x00" * 60, dst_mac="ff:ff:ff:ff:ff:ff")
        n.udp(t0 + 4 + i * 9, hmi, 5353, "224.0.0.251", 5353, b"\x00" * 12)
    return n


def multi_capture_out_of_order() -> Dict[str, Net]:
    """Two captures of one HMI polling a PLC once a second, named so the later
    capture is analyzed first.  The later file also holds a second recording
    three days after the first (a paused capture), and neither file has NTP.
    In the earlier file a test client reads one register 1,500 times in 30 s —
    a genuine hammer pattern.  Returns {file name: capture}."""
    hmi, plc, tester = "10.12.0.10", "10.12.0.20", "10.12.0.66"
    base = 1760000000.0

    def poll(session, start: float, count: int) -> None:
        for i in range(count):
            t = start + i
            session.c2s(modbus_request(i + 1, 3, 0, 4), t)
            session.s2c(modbus_read_response(i + 1, 3, [100, 200, 300, 400]), t + 0.01)
            session.ack_c(t + 0.2)

    later = Net(seed=31, start=base + 5 * 86400)
    poll(later.session(hmi, 50200, plc, 502).open(later.t0), later.t0 + 1, 600)
    resumed = later.t0 + 3 * 86400
    poll(later.session(hmi, 50201, plc, 502).open(resumed), resumed + 1, 100)

    earlier = Net(seed=32, start=base)
    poll(earlier.session(hmi, 50300, plc, 502).open(earlier.t0), earlier.t0 + 1, 600)
    hammer = earlier.session(tester, 50400, plc, 502).open(earlier.t0 + 100)
    for i in range(1500):
        t = earlier.t0 + 101 + i * 0.02
        hammer.c2s(modbus_request(i + 1, 3, 7, 1), t)
        hammer.s2c(modbus_read_response(i + 1, 3, [55]), t + 0.005)
    return {"plant_a.pcap": later, "plant_b.pcap": earlier}


def _udp_exchange(n: Net, client: str, server: str, port: int, count: int, start: float) -> None:
    """Request/reply datagrams once a second with opaque payloads (port-based detection only)."""
    for i in range(count):
        payload = bytes(n.rng.randrange(256) for _ in range(32 + i % 40))
        n.udp(start + i, client, 33279, server, port, payload)
        n.udp(start + i + 0.01, server, port, client, 33279, payload * 3)


def tristation_sis() -> Net:
    """An HMI polls a PLC over Modbus while an undeclared host holds a seven-minute
    session with a Triconex safety controller on UDP 1502 (TriStation)."""
    n = Net(seed=23)
    hmi, plc, eng, sis = "10.13.0.10", "10.13.0.20", "10.13.0.5", "10.13.0.50"
    s = n.session(hmi, 50110, plc, 502).open(n.t0)
    for i in range(60):
        t = n.t0 + 1 + i * 2
        s.c2s(modbus_request(i + 1, 3, 0, 4), t)
        s.s2c(modbus_read_response(i + 1, 3, [10, 20, 30, 40]), t + 0.01)
        s.ack_c(t + 0.2)
    _udp_exchange(n, eng, sis, 1502, 420, n.t0 + 5)
    return n


def unidentified_udp() -> Net:
    """Two hosts exchange 896 UDP datagrams on a port no OTscope detector or tshark
    dissector covers — the shape of a capture of an unknown protocol."""
    n = Net(seed=24)
    _udp_exchange(n, "10.14.0.88", "10.14.0.2", 4000, 448, n.t0 + 1)
    return n


def _tcp_exchange(n: Net, client: str, server: str, port: int, count: int, start: float, cport: int = 50500) -> None:
    """A TCP session with opaque request/reply payloads (port-based detection only)."""
    s = n.session(client, cport, server, port).open(start)
    for i in range(count):
        s.c2s(bytes(n.rng.randrange(256) for _ in range(24)), start + 1 + i)
        s.s2c(bytes(n.rng.randrange(256) for _ in range(64)), start + 1.01 + i)
        s.ack_c(start + 1.2 + i)


def ot_protocol_catalog() -> Net:
    """Catalog protocols OTscope recognizes without detailed checks: Unitronics PCOM
    (framed, decoded by tshark), CODESYS (port only), KNX/IP, GE EGD, DLMS/COSEM,
    openSAFETY, EtherCAT frames without IP, and frames of an unregistered EtherType."""
    n = Net(seed=25)
    pcom = n.session("10.15.0.5", 51000, "10.15.0.40", 20256).open(n.t0)
    ask, reply = b"/00IDED\r", b"/A00IDV100A1\r"
    for i in range(60):
        pcom.c2s(bytes([i, 0, 0x65, 0]) + len(ask).to_bytes(2, "little") + ask, n.t0 + 1 + i)
        pcom.s2c(bytes([i, 0, 0x65, 0]) + len(reply).to_bytes(2, "little") + reply, n.t0 + 1.01 + i)
    _tcp_exchange(n, "10.15.0.6", "10.15.0.41", 11740, 40, n.t0 + 2)
    _tcp_exchange(n, "10.15.0.7", "10.15.0.42", 4059, 30, n.t0 + 3, cport=50600)
    _udp_exchange(n, "10.15.0.20", "10.15.0.21", 3671, 40, n.t0 + 4)
    _udp_exchange(n, "10.15.0.30", "10.15.0.31", 18246, 40, n.t0 + 5)
    _udp_exchange(n, "10.15.0.8", "10.15.0.43", 9877, 40, n.t0 + 6)
    for i in range(300):
        n.emit(n.t0 + 7 + i * 0.002, "00:01:05:11:22:33", "ff:ff:ff:ff:ff:ff", 0x88A4,
               bytes([0x0E, 0x10]) + bytes(n.rng.randrange(256) for _ in range(40)))
    for i in range(30):
        n.emit(n.t0 + 8 + i * 0.5, "02:00:00:00:aa:01", "ff:ff:ff:ff:ff:ff", 0x88B5, bytes(46))
    return n


def custom_protocol_config() -> Net:
    """An engineering host talks to a controller on TCP 5555, a port only the site's
    config file (custom_ot_protocols) describes."""
    n = Net(seed=26)
    _tcp_exchange(n, "10.16.0.5", "10.16.0.50", 5555, 40, n.t0 + 1)
    return n


SCENARIOS = {
    "benign_modbus_hmi": benign_modbus_hmi,
    "benign_scada_master": benign_scada_master,
    "benign_office_lan": benign_office_lan,
    "windows_hmi_dual_zone": windows_hmi_dual_zone,
    "attack_creds_bruteforce": attack_creds_bruteforce,
    "attack_modbus_recon_injection": attack_modbus_recon_injection,
    "attack_arp_mitm": attack_arp_mitm,
    "av_camera_voip": av_camera_voip,
    "s7_engineering": s7_engineering,
    "arp_same_ms": arp_same_ms,
    "modbus_value_jump": modbus_value_jump,
    "attack_mitm_intercept": attack_mitm_intercept,
    "multi_capture_out_of_order": multi_capture_out_of_order,
    "tristation_sis": tristation_sis,
    "unidentified_udp": unidentified_udp,
    "ot_protocol_catalog": ot_protocol_catalog,
    "custom_protocol_config": custom_protocol_config,
}
