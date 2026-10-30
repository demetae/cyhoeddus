#!/usr/bin/env python3
import re
import sys
import copy
import datetime as dt
import xml.etree.ElementTree as ET
from pathlib import Path


def usage():
    print(f"Usage: {sys.argv[0]} appended.xml cleaned.xml", file=sys.stderr)
    sys.exit(1)


def strip_namespace(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def child(parent, name):
    for elem in parent:
        if strip_namespace(elem.tag) == name:
            return elem
    return None


def children(parent, name):
    return [elem for elem in parent if strip_namespace(elem.tag) == name]


def parse_int(value):
    try:
        return int(value)
    except Exception:
        return None


def host_key(host):
    addresses = []

    for addr in children(host, "address"):
        addr_type = addr.attrib.get("addrtype", "")
        addr_value = addr.attrib.get("addr", "")
        if addr_value:
            addresses.append((addr_type, addr_value))

    if addresses:
        return tuple(sorted(addresses))

    hostnames = child(host, "hostnames")
    if hostnames is not None:
        names = []
        for h in children(hostnames, "hostname"):
            name = h.attrib.get("name")
            if name:
                names.append(name)
        if names:
            return ("hostnames", tuple(sorted(names)))

    return ("unknown", ET.tostring(host, encoding="unicode"))


def port_key(port):
    return (
        port.attrib.get("protocol", ""),
        port.attrib.get("portid", ""),
    )


def merge_addresses(dst_host, src_host):
    existing = {
        (
            addr.attrib.get("addrtype", ""),
            addr.attrib.get("addr", ""),
        )
        for addr in children(dst_host, "address")
    }

    insert_pos = 0
    for i, elem in enumerate(list(dst_host)):
        if strip_namespace(elem.tag) == "address":
            insert_pos = i + 1

    for addr in children(src_host, "address"):
        key = (
            addr.attrib.get("addrtype", ""),
            addr.attrib.get("addr", ""),
        )
        if key not in existing:
            dst_host.insert(insert_pos, copy.deepcopy(addr))
            insert_pos += 1
            existing.add(key)


def merge_hostnames(dst_host, src_host):
    src_hostnames = child(src_host, "hostnames")
    if src_hostnames is None:
        return

    dst_hostnames = child(dst_host, "hostnames")
    if dst_hostnames is None:
        dst_host.append(copy.deepcopy(src_hostnames))
        return

    existing = {
        ET.tostring(h, encoding="unicode")
        for h in children(dst_hostnames, "hostname")
    }

    for hostname in children(src_hostnames, "hostname"):
        key = ET.tostring(hostname, encoding="unicode")
        if key not in existing:
            dst_hostnames.append(copy.deepcopy(hostname))
            existing.add(key)


def merge_host_times(dst_host, src_host):
    dst_start = parse_int(dst_host.attrib.get("starttime"))
    dst_end = parse_int(dst_host.attrib.get("endtime"))
    src_start = parse_int(src_host.attrib.get("starttime"))
    src_end = parse_int(src_host.attrib.get("endtime"))

    starts = [x for x in [dst_start, src_start] if x is not None]
    ends = [x for x in [dst_end, src_end] if x is not None]

    if starts:
        dst_host.set("starttime", str(min(starts)))
    if ends:
        dst_host.set("endtime", str(max(ends)))


def merge_ports(dst_host, src_host):
    src_ports = child(src_host, "ports")
    if src_ports is None:
        return

    dst_ports = child(dst_host, "ports")
    if dst_ports is None:
        dst_host.append(copy.deepcopy(src_ports))
        return

    existing_ports = {
        port_key(port): port
        for port in children(dst_ports, "port")
    }

    for src_port in children(src_ports, "port"):
        key = port_key(src_port)

        if key not in existing_ports:
            dst_ports.append(copy.deepcopy(src_port))
            existing_ports[key] = src_port
            continue

        # Same host/protocol/port seen again: prefer the later scan result.
        dst_port = existing_ports[key]
        dst_ports.remove(dst_port)
        new_port = copy.deepcopy(src_port)
        dst_ports.append(new_port)
        existing_ports[key] = new_port

    # Sort ports numerically for nicer client-facing output.
    port_elems = children(dst_ports, "port")
    extra_elems = children(dst_ports, "extraports")

    for elem in port_elems + extra_elems:
        dst_ports.remove(elem)

    port_elems.sort(
        key=lambda p: (
            p.attrib.get("protocol", ""),
            int(p.attrib.get("portid", "0")),
        )
    )

    for elem in port_elems:
        dst_ports.append(elem)

    for elem in extra_elems:
        dst_ports.append(elem)


def merge_host_metadata(dst_host, src_host):
    merge_addresses(dst_host, src_host)
    merge_hostnames(dst_host, src_host)
    merge_host_times(dst_host, src_host)

    singleton_tags = {
        "status",
        "times",
        "os",
        "uptime",
        "distance",
        "tcpsequence",
        "ipidsequence",
        "tcptssequence",
        "trace",
    }

    existing_tags = {strip_namespace(e.tag) for e in dst_host}

    for elem in src_host:
        tag = strip_namespace(elem.tag)

        if tag in {"address", "hostnames", "ports"}:
            continue

        if tag in singleton_tags:
            if tag not in existing_tags:
                dst_host.append(copy.deepcopy(elem))
                existing_tags.add(tag)
        else:
            serialized = ET.tostring(elem, encoding="unicode")
            duplicates = [
                ET.tostring(existing, encoding="unicode")
                for existing in children(dst_host, tag)
            ]
            if serialized not in duplicates:
                dst_host.append(copy.deepcopy(elem))


def merge_host(dst_host, src_host):
    merge_host_metadata(dst_host, src_host)
    merge_ports(dst_host, src_host)


def collect_ports_by_protocol(merged_hosts):
    ports_by_proto = {}

    for host in merged_hosts.values():
        ports = child(host, "ports")
        if ports is None:
            continue

        for port in children(ports, "port"):
            proto = port.attrib.get("protocol", "")
            portid = port.attrib.get("portid", "")

            if not proto or not portid:
                continue

            try:
                port_num = int(portid)
            except ValueError:
                continue

            ports_by_proto.setdefault(proto, set()).add(port_num)

    return ports_by_proto


def rebuild_scaninfo(merged_root, merged_hosts, scan_type_by_proto):
    for elem in list(merged_root):
        if strip_namespace(elem.tag) == "scaninfo":
            merged_root.remove(elem)

    ports_by_proto = collect_ports_by_protocol(merged_hosts)

    insert_pos = 0
    for proto in sorted(ports_by_proto):
        ports = sorted(ports_by_proto[proto])

        scaninfo = ET.Element("scaninfo")
        scaninfo.set("type", scan_type_by_proto.get(proto, "syn" if proto == "tcp" else proto))
        scaninfo.set("protocol", proto)
        scaninfo.set("numservices", str(len(ports)))
        scaninfo.set("services", ",".join(str(p) for p in ports))

        merged_root.insert(insert_pos, scaninfo)
        insert_pos += 1


def rebuild_args(merged_root, merged_hosts):
    ports_by_proto = collect_ports_by_protocol(merged_hosts)

    parts = ["nmap"]

    tcp_ports = sorted(ports_by_proto.get("tcp", []))
    udp_ports = sorted(ports_by_proto.get("udp", []))

    if tcp_ports and not udp_ports:
        parts.extend(["-p", ",".join(str(p) for p in tcp_ports)])
    elif udp_ports and not tcp_ports:
        parts.extend(["-sU", "-p", ",".join(str(p) for p in udp_ports)])
    elif tcp_ports or udp_ports:
        port_exprs = []
        if tcp_ports:
            port_exprs.append("T:" + ",".join(str(p) for p in tcp_ports))
        if udp_ports:
            port_exprs.append("U:" + ",".join(str(p) for p in udp_ports))
        parts.extend(["-p", ",".join(port_exprs)])

    # Keep this generic and clean. It avoids showing the misleading original one-port command.
    parts.extend(["-sV", "-sC", "-oX", "cleaned_nmap.xml"])

    targets = []
    for host in merged_hosts.values():
        ipv4 = None
        ipv6 = None
        fallback = None

        for addr in children(host, "address"):
            addrtype = addr.attrib.get("addrtype")
            addrval = addr.attrib.get("addr")
            if not addrval:
                continue
            if addrtype == "ipv4":
                ipv4 = addrval
            elif addrtype == "ipv6":
                ipv6 = addrval
            else:
                fallback = addrval

        targets.append(ipv4 or ipv6 or fallback)

    targets = sorted(set(t for t in targets if t))
    parts.extend(targets)

    merged_root.set("args", " ".join(parts))


def rebuild_times(merged_root, roots, merged_hosts):
    starts = []
    ends = []

    for root in roots:
        start = parse_int(root.attrib.get("start"))
        if start is not None:
            starts.append(start)

        runstats = child(root, "runstats")
        if runstats is not None:
            finished = child(runstats, "finished")
            if finished is not None:
                end = parse_int(finished.attrib.get("time"))
                if end is not None:
                    ends.append(end)

    for host in merged_hosts.values():
        start = parse_int(host.attrib.get("starttime"))
        end = parse_int(host.attrib.get("endtime"))
        if start is not None:
            starts.append(start)
        if end is not None:
            ends.append(end)

    if starts:
        earliest = min(starts)
        merged_root.set("start", str(earliest))
        merged_root.set("startstr", dt.datetime.fromtimestamp(earliest).strftime("%a %b %d %H:%M:%S %Y"))

    return min(starts) if starts else None, max(ends) if ends else None


def rebuild_runstats(merged_root, merged_hosts, start_time, end_time):
    for elem in list(merged_root):
        if strip_namespace(elem.tag) == "runstats":
            merged_root.remove(elem)

    runstats = ET.Element("runstats")

    finished = ET.SubElement(runstats, "finished")
    if end_time is not None:
        finished.set("time", str(end_time))
        finished.set("timestr", dt.datetime.fromtimestamp(end_time).strftime("%a %b %d %H:%M:%S %Y"))
    finished.set("elapsed", str(round((end_time - start_time), 2)) if start_time and end_time else "0.00")
    finished.set("summary", "Nmap done")
    finished.set("exit", "success")

    hosts_elem = ET.SubElement(runstats, "hosts")

    up = 0
    down = 0

    for host in merged_hosts.values():
        status = child(host, "status")
        if status is not None and status.attrib.get("state") == "up":
            up += 1
        else:
            down += 1

    total = up + down

    hosts_elem.set("up", str(up))
    hosts_elem.set("down", str(down))
    hosts_elem.set("total", str(total))

    merged_root.append(runstats)


def remove_duplicate_top_level_noise(merged_root):
    """
    Keep the XML cleaner for formatters.
    """
    seen_singletons = set()
    singleton_tags = {"verbose", "debugging"}

    for elem in list(merged_root):
        tag = strip_namespace(elem.tag)
        if tag in singleton_tags:
            if tag in seen_singletons:
                merged_root.remove(elem)
            else:
                seen_singletons.add(tag)


def main():
    if len(sys.argv) != 3:
        usage()

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    raw = input_path.read_text(errors="replace")

    raw = re.sub(r"<\?xml[^>]*\?>", "", raw)
    raw = re.sub(r"<!DOCTYPE[^>]*>", "", raw)
    raw = re.sub(r"<\?xml-stylesheet[^>]*\?>", "", raw)

    blocks = re.findall(r"<nmaprun\b.*?</nmaprun>", raw, flags=re.DOTALL)

    if not blocks:
        print("Error: no complete <nmaprun>...</nmaprun> blocks found.", file=sys.stderr)
        sys.exit(2)

    roots = []
    scan_type_by_proto = {}

    for i, block in enumerate(blocks, 1):
        try:
            root = ET.fromstring(block)
            roots.append(root)

            for si in children(root, "scaninfo"):
                proto = si.attrib.get("protocol")
                scan_type = si.attrib.get("type")
                if proto and scan_type:
                    scan_type_by_proto[proto] = scan_type

        except ET.ParseError as e:
            print(f"Warning: skipping malformed nmaprun block {i}: {e}", file=sys.stderr)

    if not roots:
        print("Error: no parseable nmaprun blocks found.", file=sys.stderr)
        sys.exit(3)

    merged_root = copy.deepcopy(roots[0])

    for elem in list(merged_root):
        if strip_namespace(elem.tag) in {"host", "runstats", "scaninfo"}:
            merged_root.remove(elem)

    merged_hosts = {}
    host_order = []

    for root in roots:
        for host in children(root, "host"):
            key = host_key(host)

            if key not in merged_hosts:
                merged_hosts[key] = copy.deepcopy(host)
                host_order.append(key)
            else:
                merge_host(merged_hosts[key], host)

    for key in host_order:
        merged_root.append(merged_hosts[key])

    rebuild_scaninfo(merged_root, merged_hosts, scan_type_by_proto)
    rebuild_args(merged_root, merged_hosts)
    start_time, end_time = rebuild_times(merged_root, roots, merged_hosts)
    rebuild_runstats(merged_root, merged_hosts, start_time, end_time)
    remove_duplicate_top_level_noise(merged_root)

    ET.indent(merged_root, space="  ")
    ET.ElementTree(merged_root).write(output_path, encoding="utf-8", xml_declaration=True)

    total_ports = 0
    for ports in collect_ports_by_protocol(merged_hosts).values():
        total_ports += len(ports)

    print(f"Cleaned Nmap XML written to: {output_path}")
    print(f"Merged {len(roots)} appended nmaprun block(s).")
    print(f"Final report contains {len(merged_hosts)} host(s) and {total_ports} unique port(s).")


if __name__ == "__main__":
    main()