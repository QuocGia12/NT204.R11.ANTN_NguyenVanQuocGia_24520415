## Cấu trúc thư mục: 
- `main.py`: tạo CLI 
- `Capturer_and_Parser/`: 
    - `capture.py`: duyệt danh sách các packets, gửi từng packet cho parsers.py và ghi output nhận được  
    - `parser.py`: nhận đầu vào là 1 packet, trả về Python dict chứa các field sau khi parse của packet đó 

## Phát hiện mới và thay đổi ý tưởng 
Nhận ra rằng là một application transaction khi gửi đi nếu có size lớn sẽ được separate thành nhiều tcp segments(nếu sử dụng tcp) hoặc nhiều IP fragments(nếu sử dụng udp)
→ vì thế nếu chỉ phân tích hay parser các packet riêng lẻ, ta sẽ không có được toàn bộ content payload của application transaction, dẫn đến việc không set rule dựa vào content payload của application là không thể 
→ ý tưởng mới là ta sẽ thêm gộp nhiều tcp segments hoặc ip fragments của cùng một application transaction lại với nhau để có thể đọc được toàn bộ nội dung của application transaction, từ đó mới parse nội dung đó 
→ output trả về 2 file: 
- `separated_result.json` → log các packet riêng lẻ: log toàn bộ header của tầng network và transport của packet đó và payload của tầng application(không parse)
- `application_result.json` → log các application transactions có trong quá trình caputer, parse nội dung trong các application transactions đó 

