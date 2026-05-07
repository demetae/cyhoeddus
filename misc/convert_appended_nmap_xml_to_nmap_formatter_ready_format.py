#!/usr/bin/env python3
import re
import sys
import copy
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


def host_key(host):
    """
    Build a stable identity for a host.

    Prefer IPv4/IPv6/MAC address values. Fall back to hostname if no address exists.
    """
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


def merge_addresses(dst_host, src_host):
    existing = {
        (
            addr.attrib.get("addrtype", ""),
            addr.attrib.get("addr", ""),
        )
        for addr in children(dst_host, "address")
    }

    # Insert new addresses near the top, before hostnames/ports where possible.
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

        # If the same port appears again, prefer the later result.
        dst_port = existing_ports[key]
        dst_ports.remove(dst_port)
        dst_ports.append(copy.deepcopy(src_port))
        existing_ports[key] = src_port

    # Preserve extraports elements if present and not duplicated exactly.
    existing_extra = {
        ET.tostring(e, encoding="unicode")
        for e in children(dst_ports, "extraports")
    }

    for src_extra in children(src_ports, "extraports"):
        key = ET.tostring(src_extra, encoding="unicode")
        if key not in existing_extra:
            dst_ports.append(copy.deepcopy(src_extra))
            existing_extra.add(key)


def merge_host_metadata(dst_host, src_host):
    """
    Merge useful non-port host-level fields.

    For repeated fields, this keeps the existing value unless the destination
    does not have one. Port data is handled separately.
    """
    merge_addresses(dst_host, src_host)
    merge_hostnames(dst_host, src_host)

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
            # For scripts, comments, smurf, etc., keep non-duplicates.
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


def main():
    if len(sys.argv) != 3:
        usage()

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    raw = input_path.read_text(errors="replace")

    # Remove XML declarations because appended files may contain many of them.
    raw = re.sub(r"<\?xml[^>]*\?>", "", raw)

    # Extract complete nmaprun blocks.
    blocks = re.findall(r"<nmaprun\b.*?</nmaprun>", raw, flags=re.DOTALL)

    if not blocks:
        print("Error: no complete <nmaprun>...</nmaprun> blocks found.", file=sys.stderr)
        sys.exit(2)

    roots = []
    for i, block in enumerate(blocks, 1):
        try:
            roots.append(ET.fromstring(block))
        except ET.ParseError as e:
            print(f"Warning: skipping malformed nmaprun block {i}: {e}", file=sys.stderr)

    if not roots:
        print("Error: no parseable nmaprun blocks found.", file=sys.stderr)
        sys.exit(3)

    # Use the first nmaprun as the base.
    merged_root = copy.deepcopy(roots[0])

    # Remove host/runstats from the base; rebuild them cleanly.
    for elem in list(merged_root):
        if strip_namespace(elem.tag) in {"host", "runstats"}:
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

    # Use the last runstats found.
    last_runstats = None
    for root in roots:
        rs = child(root, "runstats")
        if rs is not None:
            last_runstats = rs

    if last_runstats is not None:
        merged_root.append(copy.deepcopy(last_runstats))

    ET.indent(merged_root, space="  ")

    tree = ET.ElementTree(merged_root)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)

    print(f"Cleaned Nmap XML written to: {output_path}")
    print(f"Merged {len(roots)} nmaprun block(s) into {len(merged_hosts)} host(s).")


if __name__ == "__main__":
    main()