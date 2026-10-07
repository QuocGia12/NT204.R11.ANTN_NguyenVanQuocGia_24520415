import sys
import pyshark


def print_http_packet(packet):
    http = packet.http

    print("=" * 100)
    print(f"Packet #{packet.number}")

    # Request line
    request_method = getattr(http, "request_method", None)

    if request_method is not None:
        uri = getattr(http, "request_uri", None)
        version = getattr(http, "request_version", None)

        print(f"Type: HTTP Request")
        print(f"Request: {request_method} {uri} {version}")

    # Response line
    response_code = getattr(http, "response_code", None)

    if response_code is not None:
        version = getattr(http, "response_version", None)
        phrase = getattr(http, "response_phrase", None)

        print(f"Type: HTTP Response")
        print(f"Response: {version} {response_code} {phrase}")

    print("\nHTTP fields / headers:")
    print("-" * 100)

    for field_name in http.field_names:
        field = http.get_field(field_name)

        if field is None:
            continue

        print(f"\n[{field_name}]")

        try:
            for item in field.all_fields:
                print(f"  show       : {item.show}")
                print(f"  raw_value  : {item.raw_value}")
        except (AttributeError, TypeError):
            print(f"  value      : {field}")

    print()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <input.pcap>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    capture = pyshark.FileCapture(
        pcap_file,
        display_filter="http",
        keep_packets=False,
    )

    try:
        for packet in capture:
            if "HTTP" not in packet:
                continue

            print_http_packet(packet)

    finally:
        capture.close()


if __name__ == "__main__":
    main()