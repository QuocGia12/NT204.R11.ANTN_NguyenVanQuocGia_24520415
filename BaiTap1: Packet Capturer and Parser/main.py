import argparse 
from pathlib import Path 
from Capturer_and_Parser.capture import process_pcap, process_interface


'''
Các options cho CLI là: 
- --interface  
- --pcap 
- --output, default is ./result.json
Chỉ được sử dụng chính xác một trong 2 options đó 
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
        "--output",
        type=Path,
        default=Path("./result.json"),
        help="Identify output file, the default is result.json"
    )
    return parser 

def main(): 
    CLI = build_CLI()
    args = CLI.parse_args()
    with open(str(args.output), "w") as output_file: 
        if (args.interface): 
            process_interface(
                interface=args.interface, 
                output=output_file
            )
        else:
            process_pcap(
                pcap_file=args.pcap, 
                output=output_file
            )




if __name__ == "__main__": 
    main()