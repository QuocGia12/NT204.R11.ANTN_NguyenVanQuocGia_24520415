import argparse 


'''
Các options cho CLI là: 
- --interface  
- --pcap 
- --output, default is result.json
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
        "--pcap", help="Identify pcap file"
    )
    parser.add_argument(
        "--output", 
        default="result.json",
        help="Identify output file, the default is result.json"
    )
    return parser 

def main(): 
    CLI = build_CLI()
    args = CLI.parse_args()
    print(args.interface, args.pcap, args.output)

'''
Note: 
+ change type of pcap file and output from string to Path 
'''

if __name__ == "__main__": 
    main()