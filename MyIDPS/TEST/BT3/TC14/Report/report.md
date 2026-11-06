## Test Case 14

> Detection Event có sid/msg/flow/5-tuple/protocol/match info.

Em sử dụng `test13.rules` để test, có nội dung sau: 
```
alert tcp 127.0.0.1 any -> 127.0.0.1 8000 (msg:"TEST 1"; flags:S; sid:6000001; rev:1;)
```

Sau đó em thực hiện kết nối đến localhost 80 bằng lệnh `nc localhost 8000`

Kết quả: 
```
{"event_type": "alert", "timestamp": "2026-11-06 15:52:23.964826", "packet_number": "68", "flow_id": "flow-000022", "rule": {"action": "alert", "protocol": "TCP", "msg": "TEST 1", "sid": 6000001, "rev": 1, "flow": [], "flags": {"mode": "exact", "required": ["S"], "forbidden": []}, "content_count": 0, "raw": "alert tcp 127.0.0.1 any -> 127.0.0.1 8000 (msg:\"TEST 1\"; flags:S; sid:6000001; rev:1;)", "line_number": 1}, "packet": {"number": "68", "timestamp": "2026-11-06 15:52:23.964826", "protocol": "TCP", "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 45942, "dst_port": 8000, "payload_length": 0, "dsize": 0, "tcp_flags": ["S"], "flow_id": "flow-000022", "flow_direction": "to_server", "flow_flags": ["not_established", "to_server"]}, "match": {"protocol": "TCP", "direction": "to_server", "matched_contents": [], "dsize": 0, "tcp_flags": ["S"], "flags": "S"}}


```
Nhận xét: detection event có đủ các trường mong muốn: 
- `sid`: `6000001`
- `msg`: `TEST 1`
- `flow_id`: `flow-000022`
- `5-tuple`:
    - `Source IP`: `127.0.0.1`
    - `Source Port`: `45942`
    - `Destination IP`: `127.0.0.1`
    - `Destination Port`: `8000`
    - `Protocol`: `TCP`
- `protocol`: `TCP`
- `match info`:
    - `Direction`: `to_server`
    - `Matched contents`: `[]`
    - `Dsize`: `0`
    - `TCP flags`: `S`
