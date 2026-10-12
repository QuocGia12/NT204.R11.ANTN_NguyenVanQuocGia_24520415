## Kết quả 
Trường `body_url_decode` decode thành công http body có MIME là `application/x-www-form-urlencoded` 
## Ví dụ minh chứng 
Packet đầu tiên trong `test_body_url_decode.pcap` là HTTP POST request có `Content-Type` là `application/x-www-form-urlencoded` và `body` là `username=admin&password=hello+world`
Tương ứng thì kết quả trường `body_url_decode` của em là `username=admin&password=hello world`, đã decode thành công `+` thành ` `