## Cấu trúc thư mục: 
- `main.py`: tạo CLI 
- `Capturer_and_Parser/`: 
    - `capture.py`: duyệt danh sách các packets, gửi từng packet cho parsers.py và ghi output nhận được  
    - `parser.py`: nhận đầu vào là 1 packet, trả về Python dict chứa các field sau khi parse của packet đó 

