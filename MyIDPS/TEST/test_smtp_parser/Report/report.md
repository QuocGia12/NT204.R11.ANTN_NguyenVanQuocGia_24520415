## Kết quả 
Phân loại thành công một SMTP message thành các loại:; 
- request -> request từ client -> parse thành công `command` và `arg`
- response -> response của server -> parse thành công `respone code` và `message`
- auth -> User và Pass -> parse thành công username và password, tuy nhiên không log password  
- data -> nội dung mail -> parse thành công nội dung mail 
## Minh chứng ví dụ: 
### Request
Trong packet thứ 8 có STMP request có command là `EHLO` và `arg` là `lab.local`
![alt text](image.png)

Tương ứng thì em cũng parse được command là `EHLO` và `arg` là `lab.local`
```json 
{"number": "8", "sniff_time": "2026-10-12 21:50:58.704489", "network": {"protocol": "IP", "source_ip": "127.0.0.1", "dest_ip": "127.0.0.1"}, "transport": {"protocol": "tcp", "source_port": "57398", "dest_port": "25"}, "application": {"protocol": "SMTP", "type": "request", "command": "EHLO", "arg": "lab.local"}, "flow_id": "flow-000001"}

```
### Response 
Trong packet thứ 10 có SMTP response code `response code` là 250, `message` là `localhost`
![alt text](image-1.png)

Tương ứng thì em cũng parse được response code `response code` là 250, `message` là `localhost`
```json
{"number": "10", "sniff_time": "2026-10-12 21:50:58.705595", "network": {"protocol": "IP", "source_ip": "127.0.0.1", "dest_ip": "127.0.0.1"}, "transport": {"protocol": "tcp", "source_port": "25", "dest_port": "57398"}, "application": {"protocol": "SMTP", "type": "response", "response_code": "250", "message": "localhost"}, "flow_id": "flow-000001"}

```
### Data 
Trong packet thứ 60 gửi đi data 
![alt text](image-2.png)

Tương ứng thì em cũng parse được data của mail đó: 
- from 
- to 
- content-type 
- subject 
- data 
```json 
{"number": "60", "sniff_time": "2026-10-12 21:51:36.379527", "network": {"protocol": "IP", "source_ip": "127.0.0.1", "dest_ip": "127.0.0.1"}, "transport": {"protocol": "tcp", "source_port": "57398", "dest_port": "25"}, "application": {"protocol": "SMTP", "type": "data", "tcp_stream": "0", "imf": {"protocol": "IMF", "fields": {"from": "alice@test.local", "mailbox_list_item": "alice@test.local ", "address": ["alice@test.local ", "bob@test.local "], "to": "bob@test.local", "address_list_item": "bob@test.local ", "subject": "SMTP Test", "content_type": "text/plain; charset=UTF-8", "content_type_type": "text/plain", "content_type_parameters": " charset=UTF-8", "data": ["Hello qgiaaa\\r\\n", "\\r\\n"]}}, "data_fragment_count": "7", "data_reassembled_length": "123", "data_fragments": ["36", "40", "44", "48", "50", "54", "56"]}, "flow_id": "flow-000001"}

```