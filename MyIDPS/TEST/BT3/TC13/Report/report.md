## Test Case 13 

> Một event match đồng thời >= 2 rule thì sẽ sinh nhiều detection event tương ứng 

Em sử dụng `test12.rules` để test, có nội dung sau: 
```
# TEST 1
alert tcp 127.0.0.1 any -> 127.0.0.1 8000 (msg:"TEST 1"; flags:S; sid:6000001; rev:1;)

# TEST 2
alert tcp 127.0.0.1 any -> any 8000 (msg:"TEST 2"; flags:S; sid:6000002; rev:1;)
```

Sau đó em thực hiện kết nối đến localhost 80 bằng lệnh `nc localhost 8000`

Ta thấy cả 2 rule đều match với hành động của ta, như mong muốn thì sẽ có 2 detection events sinh ra 

Kết quả: 
```
{"event_type": "alert", "timestamp": "2026-11-06 15:49:57.029551", "packet_number": "68", "flow_id": "flow-000022", "rule": {"action": "alert", "protocol": "TCP", "msg": "TEST 1", "sid": 6000001, "rev": 1, "flow": [], "flags": {"mode": "exact", "required": ["S"], "forbidden": []}, "content_count": 0, "raw": "alert tcp 127.0.0.1 any -> 127.0.0.1 8000 (msg:\"TEST 1\"; flags:S; sid:6000001; rev:1;)", "line_number": 2}, "packet": {"number": "68", "timestamp": "2026-11-06 15:49:57.029551", "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 55230, "dst_port": 8000, "payload_length": 0, "dsize": 0, "tcp_flags": ["S"], "flow_id": "flow-000022", "flow_direction": "to_server", "flow_flags": ["not_established", "to_server"]}, "match": {"protocol": "TCP", "direction": "to_server", "matched_contents": [], "dsize": 0, "tcp_flags": ["S"], "flags": "S"}}

{"event_type": "alert", "timestamp": "2026-11-06 15:49:57.029551", "packet_number": "68", "flow_id": "flow-000022", "rule": {"action": "alert", "protocol": "TCP", "msg": "TEST 2", "sid": 6000002, "rev": 1, "flow": [], "flags": {"mode": "exact", "required": ["S"], "forbidden": []}, "content_count": 0, "raw": "alert tcp 127.0.0.1 any -> any 8000 (msg:\"TEST 2\"; flags:S; sid:6000002; rev:1;)", "line_number": 5}, "packet": {"number": "68", "timestamp": "2026-11-06 15:49:57.029551", "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 55230, "dst_port": 8000, "payload_length": 0, "dsize": 0, "tcp_flags": ["S"], "flow_id": "flow-000022", "flow_direction": "to_server", "flow_flags": ["not_established", "to_server"]}, "match": {"protocol": "TCP", "direction": "to_server", "matched_contents": [], "dsize": 0, "tcp_flags": ["S"], "flags": "S"}}

```
Nhận xét: đúng như mong muốn, có 2 detection events sinh ra ứng với rule 1 và 2 đó 
