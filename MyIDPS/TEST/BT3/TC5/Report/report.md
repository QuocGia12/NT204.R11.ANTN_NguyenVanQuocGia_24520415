## Test Case 5 
> Direction `->` và `<>` hoạt động đúng 

Để test chức năng em sử dụng 2 files rule `test5_1.rules` và `test5_2.rules`: 
- `test5_1.rules`: `alert tcp 127.0.0.1 12345 -> 127.0.0.1 80`
- `test5_2.rules`: `alert tcp 127.0.0.1 12345 <-> 127.0.0.1 80`

Tức `test5_1.rules` là 1 chiều còn `test5_2.rules` là 2 chiều 

### Test 1 chiều 

Đầu tiên em thử chạy với rule 1 chiều `test5_1.rules`

Sau đó thực hiện lệnh `nc -p 12345 localhost 80`(kết nối đến localhost port 80 sử dụng source port là 12345)

Kết quả các detection event ta có được như sau: 
```
{"event_type": "alert", "timestamp": "2026-11-06 11:17:55.311417", "packet_number": "298", "flow_id": "flow-000023", "rule": {"action": "alert", "protocol": "TCP", "msg": "TEST - TCP unidirectional", "sid": 5000001, "rev": 1, "flow": [], "content_count": 0, "raw": "alert tcp 127.0.0.1 12345 -> 127.0.0.1 80 (msg:\"TEST - TCP unidirectional\"; sid:5000001; rev:1;)", "line_number": 2}, "packet": {"number": "298", "timestamp": "2026-11-06 11:17:55.311417", "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 12345, "dst_port": 80, "payload_length": 0, "dsize": 0, "tcp_flags": ["S"], "flow_id": "flow-000023", "flow_direction": "to_server", "flow_flags": ["not_established", "to_server"]}, "match": {"protocol": "TCP", "direction": "to_server", "matched_contents": [], "dsize": 0, "tcp_flags": ["S"], "flags": "S"}}

{"event_type": "alert", "timestamp": "2026-11-06 11:17:55.311450", "packet_number": "300", "flow_id": "flow-000023", "rule": {"action": "alert", "protocol": "TCP", "msg": "TEST - TCP unidirectional", "sid": 5000001, "rev": 1, "flow": [], "content_count": 0, "raw": "alert tcp 127.0.0.1 12345 -> 127.0.0.1 80 (msg:\"TEST - TCP unidirectional\"; sid:5000001; rev:1;)", "line_number": 2}, "packet": {"number": "300", "timestamp": "2026-11-06 11:17:55.311450", "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 12345, "dst_port": 80, "payload_length": 0, "dsize": 0, "tcp_flags": ["A"], "flow_id": "flow-000023", "flow_direction": "to_server", "flow_flags": ["established", "to_server"]}, "match": {"protocol": "TCP", "direction": "to_server", "matched_contents": [], "dsize": 0, "tcp_flags": ["A"], "flags": "A"}}

```

Tức nó chỉ match với các packet `S` và `A` từ `localhost:12345` đến `localhost:80`, không match với gói `SA` từ `localhost:80` gửi về -> đúng như mong muốn 

### Test 2 chiều 
Tiếp theo, em chạy với rule 2 chiều `test5_2.rules`, đồng thời cũng sử dụng `nc -p 12345 localhost 80` sau đó thì kết quả các detection event nhận được là: 
```
{"event_type": "alert", "timestamp": "2026-11-06 11:23:18.238913", "packet_number": "51", "flow_id": "flow-000023", "rule": {"action": "alert", "protocol": "TCP", "msg": "TEST - TCP bidirectional", "sid": 5000002, "rev": 1, "flow": [], "content_count": 0, "raw": "alert tcp 127.0.0.1 12345 <> 127.0.0.1 80 (msg:\"TEST - TCP bidirectional\"; sid:5000002; rev:1;)", "line_number": 2}, "packet": {"number": "51", "timestamp": "2026-11-06 11:23:18.238913", "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 12345, "dst_port": 80, "payload_length": 0, "dsize": 0, "tcp_flags": ["S"], "flow_id": "flow-000023", "flow_direction": "to_server", "flow_flags": ["not_established", "to_server"]}, "match": {"protocol": "TCP", "direction": "to_server", "matched_contents": [], "dsize": 0, "tcp_flags": ["S"], "flags": "S"}}

{"event_type": "alert", "timestamp": "2026-11-06 11:23:18.238940", "packet_number": "52", "flow_id": "flow-000023", "rule": {"action": "alert", "protocol": "TCP", "msg": "TEST - TCP bidirectional", "sid": 5000002, "rev": 1, "flow": [], "content_count": 0, "raw": "alert tcp 127.0.0.1 12345 <> 127.0.0.1 80 (msg:\"TEST - TCP bidirectional\"; sid:5000002; rev:1;)", "line_number": 2}, "packet": {"number": "52", "timestamp": "2026-11-06 11:23:18.238940", "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 80, "dst_port": 12345, "payload_length": 0, "dsize": 0, "tcp_flags": ["A", "S"], "flow_id": "flow-000023", "flow_direction": "to_client", "flow_flags": ["not_established", "to_client"]}, "match": {"protocol": "TCP", "direction": "to_client", "matched_contents": [], "dsize": 0, "tcp_flags": ["A", "S"], "flags": "AS"}}

{"event_type": "alert", "timestamp": "2026-11-06 11:23:18.238954", "packet_number": "53", "flow_id": "flow-000023", "rule": {"action": "alert", "protocol": "TCP", "msg": "TEST - TCP bidirectional", "sid": 5000002, "rev": 1, "flow": [], "content_count": 0, "raw": "alert tcp 127.0.0.1 12345 <> 127.0.0.1 80 (msg:\"TEST - TCP bidirectional\"; sid:5000002; rev:1;)", "line_number": 2}, "packet": {"number": "53", "timestamp": "2026-11-06 11:23:18.238954", "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 12345, "dst_port": 80, "payload_length": 0, "dsize": 0, "tcp_flags": ["A"], "flow_id": "flow-000023", "flow_direction": "to_server", "flow_flags": ["established", "to_server"]}, "match": {"protocol": "TCP", "direction": "to_server", "matched_contents": [], "dsize": 0, "tcp_flags": ["A"], "flags": "A"}}

```
Kết quả đúng như mong muốn, rule match 2 chiều, match luôn cả chiều từ `localhost:80` đến `localhost:12345`(có detection event của gói `SA`)