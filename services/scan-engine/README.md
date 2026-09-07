# Scan Engine — Anti-Scam Platform (mốc M1)

Rule engine **giải thích được** cho nội dung tin nhắn tiếng Việt.
Nhận một đoạn text, trả về điểm rủi ro 0–100, mức cảnh báo `SAFE`/`CAUTION`/`DANGER`,
danh sách bằng chứng theo từng rule và khuyến nghị hành động.

Hợp đồng JSON bám đúng [`API_Specification.md` mục 2.2](../../document/Week2/02_Phan_Tich_Nghiep_Vu/API_Specification.md).

> **Nguyên tắc cốt lõi:** mọi điểm đều đi kèm một `ruleCode` truy ngược được về
> [`app/data/rules.json`](app/data/rules.json). Không có điểm nào do mô hình sinh ra
> mà không giải thích được. Đây là ràng buộc của đề tài, không phải lựa chọn kỹ thuật.

---

## Chạy

```bash
cd services/scan-engine
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

- API docs (Swagger): <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>

## Test

**Postman** — import [`postman/AntiScam-ScanEngine-M1.postman_collection.json`](postman/AntiScam-ScanEngine-M1.postman_collection.json)
rồi bấm **Run collection**. 16 request, 5 nhóm:

| Nhóm | Nội dung |
|---|---|
| 0 · Hạ tầng | health, danh sách rule đang hoạt động |
| 1 · Nghiệp vụ | 6 mẫu lừa đảo phải bắt được → `DANGER` |
| 2 · Chống báo động giả | 3 nội dung lành tính phải ra `SAFE` |
| 3 · Hợp đồng JSON | kiểm tra đúng spec + tính xác định (gửi 2 lần ra cùng điểm) |
| 4 · Validate | text rỗng / quá 5000 ký tự / source sai → `400` |

**pytest** — cùng bộ case, dùng cho CI:

```bash
python -m pytest tests/ -q
```

---

## Endpoint

### `POST /v1/scan/text`

```json
{ "text": "Tài khoản sắp bị khóa, xác minh tại http://vietc0mbank.com", "source": "SMS", "saveHistory": true }
```

`source` ∈ `SMS` · `ZALO` · `MESSENGER` · `EMAIL` · `FACEBOOK` · `OTHER`.
`text` từ 1 đến 5000 ký tự.

Trả về `200` với `{ success, data }`, trong đó `data` gồm `scanId`, `input`,
`result`, `analysis`, `evidences[]`, `recommendation`, `scannedAt`, `processingTime`.

Lỗi validate trả `400`:

```json
{ "success": false, "error": { "code": "VALIDATION_ERROR", "message": "...", "details": [ { "field": "text", "message": "..." } ] } }
```

### `GET /v1/rules/active`

Metadata của rule (`code`, `name`, `category`, `weight`, `severity`).
Cố ý **không** trả điều kiện khớp, để kẻ tấn công không đọc được cách né bộ lọc.

### `GET /health`

---

## Pipeline

```
text
 └─1─ normalize     hạ chữ thường, bỏ dấu, gỡ leetspeak (vi3tc0mb4nk → vietcombank)
 └─2─ extract       URL · số điện thoại · số tài khoản · số tiền · mã OTP
 └─3─ keywords      6 nhóm từ khoá tiếng Việt
 └─4─ domains       whitelist · TLD rác · rút gọn link · IP trần · typosquatting
 └─5─ facts         gom tất cả thành một tập FACT
 └─6─ evaluate      chạy 16 rule trên tập FACT → evidences[]
 └─7─ score         cộng điểm → clamp [0,100] → SAFE / CAUTION / DANGER → khuyến nghị
```

### Vì sao tách `normalize` và `normalize_light`

`normalize_light()` chỉ bỏ dấu. `normalize()` bỏ dấu **và** gỡ leetspeak.
Nếu tên thương hiệu chỉ xuất hiện ở bản `normalize()` mà không có ở bản
`normalize_light()` thì người gửi đã cố tình viết biến thể để né bộ lọc — đó chính
là fact `LEET_BRAND`, một tín hiệu rất mạnh. Leetspeak chỉ áp dụng cho token có
chứa chữ cái, nên `100` và `0912345678` không bị đụng tới.

### Mô hình rule

Mỗi rule chỉ làm một việc: so khớp tập FACT.

```json
{
  "code": "PATTERN_BANK_IMPERSONATION",
  "name": "Mẫu lừa đảo giả mạo ngân hàng",
  "severity": "CRITICAL",
  "score": 30,
  "pattern": true,
  "requiresAll": ["BRAND:BANK"],
  "requiresAny": ["GROUP:URGENCY", "GROUP:SENSITIVE_INFO"]
}
```

Cấu trúc này ánh xạ thẳng sang hai bảng `risk_rules` / `rule_conditions` của
PostgreSQL ở mốc M2 — đổi nguồn nạp rule từ file sang DB mà không phải viết lại logic.

### Từ vựng FACT

| Nhóm | Fact |
|---|---|
| Từ khoá | `GROUP:URGENCY` `GROUP:IMPERSONATION` `GROUP:SENSITIVE_INFO` `GROUP:MONEY_TRANSFER` `GROUP:TOO_GOOD` `GROUP:JOB_OFFER` |
| Thương hiệu | `BRAND:BANK` `BRAND:AUTHORITY` `BRAND:SHIPPER` `LEET_BRAND` |
| Thực thể | `HAS_URL` `HAS_HTTP_URL` `HAS_PHONE` `HAS_BANK_ACCOUNT` `HAS_AMOUNT` `HAS_OTP` |
| Tên miền | `URL_TYPOSQUAT` `URL_SUSPICIOUS_TLD` `URL_SHORTENER` `URL_IP_HOST` `URL_ALL_WHITELISTED` |

Response trả kèm `analysis.matchedFacts` để debug — nhìn là biết vì sao rule khớp hoặc không khớp.

### Thêm rule mới

Sửa [`app/data/rules.json`](app/data/rules.json), thêm test tương ứng vào
[`tests/test_scan_text.py`](tests/test_scan_text.py), chạy `pytest`. Không cần sửa code.
Ngưỡng `CAUTION` = 40 và `DANGER` = 70 nằm ở `thresholds` cùng file.

---

## Giới hạn đã biết ở M1

- **Chưa lưu gì cả.** `saveHistory` được nhận nhưng chưa dùng — chưa có DB (mốc M2).
- **Chưa có auth.** Endpoint đang mở (mốc M3).
- **Không truy cập mạng.** Không fetch URL, không theo redirect, không kiểm tra SSL/WHOIS.
  Việc đó thuộc URL Scanner Worker (slice Khải) và cần SSRF guard riêng.
- **Trọng số đang là phỏng đoán ban đầu.** Hiện chỉnh tay để 12 case mẫu ra đúng.
  Muốn bảo vệ được trước hội đồng thì phải gán nhãn một tập dữ liệu thật rồi đo
  Precision/Recall — đó là việc của mốc M4.
- **Còn báo động giả đã biết:** SMS OTP hợp lệ của ngân hàng ("Mã OTP của bạn là …")
  hiện rơi vào `CAUTION`. Cần thêm rule nhận diện tin OTP chính danh, hoặc chấp nhận
  vì khuyến cáo thận trọng với tin chứa OTP cũng không sai.

## Mốc tiếp theo

| Mốc | Nội dung |
|---|---|
| M2 | PostgreSQL + `scan_requests` / `risk_results` (JSONB) + `GET /v1/scan/{scanId}` |
| M3 | JWT auth, gắn `userId`, `GET /v1/scan/history` |
| M4 | Lớp LLM sau feature flag `ai.enabled` — chỉ thêm phần diễn giải, **không** đổi điểm; đo Precision/Recall rule-only vs hybrid |
| M5 | Async qua RabbitMQ (`202` + `scanId` rồi poll) — chỉ làm nếu còn thời gian |

## Lưu ý phân công

`POST /v1/scan/text` đang thuộc **Slice 3** trong
[`Tong_hop_Feature_List_Week4.md`](../../document/Week4/Tong_hop_Feature_List_Week4.md).
Cần chốt ranh giới với nhóm trước khi mở rộng service này, tránh code đè lên nhau.
