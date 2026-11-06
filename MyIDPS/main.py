import argparse 
from pathlib import Path 
try:
    from .Capturer_and_Parser.capture import process_pcap, process_interface
    from .Core_Engine import RuleLoader, RuleMatcher, RuleRepository
except ImportError:  # Support running main.py directly from the MyIDPS folder.
    from Capturer_and_Parser.capture import process_pcap, process_interface
    from Core_Engine import RuleLoader, RuleMatcher, RuleRepository


'''
Các options cho CLI là: 
- --interface  
- --pcap 
- --output_packet, default is ./packet_result.json
- --output_application, default is ./application_result.json
- --rules, optional Snort rules file
- --output_detection, default is ./detection_result.json

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
    parser.add_argument(
        "--output_flow",
        type=Path,
        default=Path("./flow_result.json"),
        help="Identify output file for flow table result, the default is flow_result.json"
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="Identify the Snort .rules file; omit to disable detection",
    )
    parser.add_argument(
        "--output_detection",
        type=Path,
        default=Path("./detection_result.json"),
        help="Identify output file for detection events, the default is detection_result.json",
    )
    return parser 

def main(): 
    CLI = build_CLI()
    args = CLI.parse_args()
    repository = None
    if args.rules is not None:
        report = RuleLoader().load(args.rules)
        repository = RuleRepository(report.rules)
    matcher = RuleMatcher()

    with (
        open(str(args.output_packet), "w") as output_packet,
        open(str(args.output_application), "w") as output_application,
        open(str(args.output_flow), "w") as output_flow,
        open(str(args.output_detection), "w") as output_detection,
    ):
        if (args.interface): 
            process_interface(
                interface=args.interface, 
                output_packet=output_packet,
                output_application=output_application,
                output_flow=output_flow,
                output_detection=output_detection,
                repository=repository,
                matcher=matcher,
            )
        else:
            process_pcap(
                pcap_file=args.pcap, 
                output_packet=output_packet,
                output_application=output_application, 
                output_flow=output_flow,
                output_detection=output_detection,
                repository=repository,
                matcher=matcher,
            )




if __name__ == "__main__": 
    main()
