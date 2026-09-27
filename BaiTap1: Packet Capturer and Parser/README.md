## Cấu trúc thư mục: 
- `main.py`: tạo CLI 
- `Capturer_and_Parser/`: 
    - `capture.py`: duyệt danh sách các packets, gửi từng packet cho parsers.py và ghi output nhận được  
    - `parser.py`: nhận đầu vào là 1 packet, trả về Python dict chứa các field sau khi parse của packet đó 

## Phát hiện mới và thay đổi ý tưởng 
Nhận ra rằng là một application message khi gửi đi nếu có size lớn sẽ được separate thành nhiều tcp segments(nếu sử dụng tcp) hoặc nhiều IP fragments(nếu sử dụng udp)
→ vì thế nếu chỉ phân tích hay parser các packet riêng lẻ, ta sẽ không có được toàn bộ content payload của application message, dẫn đến việc không set rule dựa vào content payload của application là không thể 
→ ý tưởng mới là ta sẽ thêm gộp nhiều tcp segments hoặc ip fragments của cùng một application message lại với nhau để có thể đọc được toàn bộ nội dung của application message, từ đó mới parse nội dung đó 
→ output trả về 2 file: 
- `packet_result.json` → log các packet riêng lẻ: log toàn bộ header của tầng network và transport của packet đó và payload của tầng application(không parse)
- `application_result.json` → log các application messages có trong quá trình caputer, parse nội dung trong các application messages đó 

Ý tưởng mới là ta sẽ sử dụng `pyshark` thay vì `scapy` vì `pyshark` hỗ trợ tcp desegment và ip defragment (giống wireshark thì packet cuối cùng hoàn tất tcp desegment hoặc ip defragment, tức hoàn tất ghép thành một application message sẽ có thêm một lớp application nữa ngoài transport payload mà nó mang)
Flow code sẽ như sau: 
- Duyệt danh sách các packet 
- Ứng với mỗi packet: 
    - Parse và log packet đó vào `packet_result.json`(network layer fields, transport layer fields, transport payload)
    - Nếu có layer application thì parse application và log (src ip, src port, dst ip, dst port, application fields) vào `application_result.json`


