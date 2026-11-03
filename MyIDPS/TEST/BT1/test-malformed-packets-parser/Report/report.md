## Tạo malformed-packets
File `malformed.pcap` được tạo manually với lệnh sau: `editcap -E 0.99 TEST/test-http-post/test-http-post.pcap malformed.pcap`
-> lệnh này sẽ lấy input là `TEST/test-http-post/test-http-post.pcap`, chỉnh sửa nó thành malformed một cách random rồi output file `malformed.pcap`
## Kết quả 
Chương trình vẫn chạy bình thường, không crash, các protocol không detect được đều là `UNKNOWN`
```json
{"number": "1", "sniff_time": "2005-03-05 21:33:04.899920", "network": {"protocol": "UNKNOWN"}, "transport": {"protocol": "UNKNOWN"}, "payload": "UNKNOWN"}
{"number": "2", "sniff_time": "2005-03-05 21:33:04.899976", "network": {"protocol": "UNKNOWN"}, "transport": {"protocol": "UNKNOWN"}, "payload": "UNKNOWN"}
{"number": "3", "sniff_time": "2005-03-05 21:33:04.899981", "network": {"protocol": "UNKNOWN"}, "transport": {"protocol": "UNKNOWN"}, "payload": "UNKNOWN"}
{"number": "4", "sniff_time": "2005-03-05 21:33:05.015011", "network": {"protocol": "UNKNOWN"}, "transport": {"protocol": "UNKNOWN"}, "payload": "UNKNOWN"}
{"number": "5", "sniff_time": "2005-03-05 21:33:05.015074", "network": {"protocol": "UNKNOWN"}, "transport": {"protocol": "UNKNOWN"}, "payload": "UNKNOWN"}
{"number": "6", "sniff_time": "2005-03-05 21:33:05.016156", "network": {"protocol": "UNKNOWN"}, "transport": {"protocol": "UNKNOWN"}, "payload": "UNKNOWN"}
{"number": "7", "sniff_time": "2005-03-05 21:33:05.016727", "network": {"protocol": "UNKNOWN"}, "transport": {"protocol": "UNKNOWN"}, "payload": "UNKNOWN"}
```