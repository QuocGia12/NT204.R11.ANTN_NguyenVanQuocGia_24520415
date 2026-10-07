import argparse 
from pathlib import Path 
from Capturer_and_Parser.capture import process_pcap, process_interface


'''
Các options cho CLI là: 
- --interface  
- --pcap 
- --output_packet, default is ./packet_result.json
- --output_application, default is ./application_result.json

Chỉ được sử dụng chính xác một trong 2 options interface và pcap 
'''
def build_CLI() -> argparse.ArgumentParser: 
    parser = argparse.ArgumentParser(
        description='The program for capturing and parsering packets, use --interface for live capturing or use --pcap for importing pcap file'
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--interface", help="Identify network interface for live capturing"
    )
    source.add_argument(
        "--pcap",
        type=Path, 
        help="Identify pcap file"
    )
    parser.add_argument(
        "--output_packet",
        type=Path,
        default=Path("./packet_result.json"),
        help="Identify output file for packet result, the default is packet_result.json"
    )
    parser.add_argument(
        "--output_application",
        type=Path,
        default=Path("./application_result.json"),
        help="Identify output file for application result, the default is application_result.json"
    )
    return parser 

def main(): 
    CLI = build_CLI()
    args = CLI.parse_args()
    with open(str(args.output_packet), "w") as output_packet, open(str(args.output_application), "w") as output_application: 
        if (args.interface): 
            process_interface(
                interface=args.interface, 
                output_packet=output_packet,
                output_application=output_application
            )
        else:
            process_pcap(
                pcap_file=args.pcap, 
                output_packet=output_packet,
                output_application=output_application
            )




if __name__ == "__main__": 
    main()