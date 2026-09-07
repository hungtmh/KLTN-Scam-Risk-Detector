## Mã nhóm tính năng
<!-- Ví dụ: H02 · Đăng nhập & quản lý phiên -->

## PR này làm gì
<!-- 1-3 câu, viết cho người KHÔNG làm phần này.
     Tốt:   "Thêm luồng đăng nhập cấp JWT 15 phút + refresh token 7 ngày có xoay vòng."
     Không: "Update auth", "Fix theo comment", "Làm tiếp phần hôm qua". -->

## Vì sao làm theo cách này
<!-- Chỉ điền khi có lựa chọn không hiển nhiên.
     Nói trước lý do thì người review không phải đoán rồi hỏi lại. -->

## Loại thay đổi
- [ ] `feat` — thêm tính năng
- [ ] `fix` — sửa lỗi
- [ ] `refactor` — sửa cấu trúc, không đổi hành vi
- [ ] `test` — chỉ thêm test
- [ ] `docs` — chỉ sửa tài liệu
- [ ] `chore` — cấu hình, CI, phụ thuộc

## Cách kiểm chứng
<!-- Lệnh copy-dán chạy được ngay, hoặc các bước bấm trên giao diện.
     Người review PHẢI chạy được, không chỉ đọc code. -->

```bash

```

## Ảnh hưởng tới người khác
- [ ] Không ảnh hưởng ai
- [ ] Có — điền bảng dưới

| Ảnh hưởng gì | Ai | Họ cần làm gì |
|---|---|---|
|  |  |  |

## Checklist trước khi xin review
- [ ] CI xanh
- [ ] Có test cho đường đúng **và** ít nhất một đường sai
- [ ] Không commit khoá / mật khẩu / token
- [ ] Không log mật khẩu, OTP, số thẻ, số tài khoản đầy đủ, SĐT đầy đủ
- [ ] Đã cập nhật `contracts/openapi/` nếu đổi hợp đồng API
- [ ] Đã cập nhật `.env.example` nếu thêm biến môi trường
- [ ] Migration chạy được từ database rỗng
- [ ] File mới có khối comment đầu file nói rõ trách nhiệm

## Báo cáo tính năng
<!-- Link tới BCTN nếu PR này đóng trọn một nhóm tính năng.
     Nếu chưa: ghi "Chưa — còn thiếu <phần gì>, dự kiến PR sau". -->

## Ảnh chụp màn hình
<!-- Bắt buộc nếu PR đụng vào giao diện. Kèm cả trạng thái lỗi, không chỉ trạng thái đẹp. -->

---
<sub>Chuẩn báo cáo: <a href="../document/Week6/05_Chuan_bao_cao_code/00_Quy_dinh_bao_cao_code.md">document/Week6/05_Chuan_bao_cao_code</a></sub>
