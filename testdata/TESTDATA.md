# ErrSec Testdata

แต่ละ case อยู่ใน `testdata/cases/<case_name>/` เป็น Go package ที่ compile ได้

## วิธีรัน

```bash
# รัน ErrSec บน case ที่ต้องการ
./errsec ./testdata/cases/blank_db
./errsec ./testdata/cases/blank_auth
./errsec ./testdata/cases/check_pattern
# ...

# รันทุก case
for d in testdata/cases/*/; do
    echo "=== $d ==="
    ./errsec ./$d
done
```

---

## สรุป Coverage ของ Test Cases

| Case | Package | Pattern | Risk | Mutation | FR/NFR ที่ทดสอบ |
|------|---------|---------|------|----------|-----------------|
| blank_db | database/sql | PatternBlank | HIGH | discarded | FR-03, FR-05 |
| blank_auth | crypto/ | PatternBlank | HIGH | discarded | FR-03, FR-05 |
| blank_network | net/http | PatternBlank | HIGH | discarded | FR-03, FR-05 |
| blank_low_risk | fmt, log/slog | PatternBlank | LOW | discarded | FR-03, FR-05 |
| check_pattern | database/sql | PatternCheck | HIGH | propagated/discarded | FR-03, FR-06 |
| defer_flow | database/sql | PatternBlank/Check | HIGH | — | FR-04 (Smart CFG defer) |
| mutation_wrapped | database/sql, net/http | PatternCheck | HIGH | wrapped | FR-06 (MutationWrapped) |
| mutation_discarded | database/sql, net/http | PatternCheck | HIGH | discarded | FR-06 (MutationDiscarded) |
| interprocedural | database/sql | PatternBlank/Check | HIGH | — | FR-07 (summary store) |
| complexity_cap | database/sql | PatternBlank | HIGH | — | FR-08 (N=1000 cap) |
| multireturn | database/sql, net/http | PatternBlank/Check | HIGH | — | FR-03 (tuple extraction) |
| mixed | database/sql, crypto/, net/http, fmt | PatternBlank/Check | HIGH+LOW | all | FR-03–09 combined |

---

## รายละเอียดแต่ละ Case

### 01 `blank_db` — PatternBlank + database/sql (HIGH)

**สิ่งที่ทดสอบ:**
- `_ = db.QueryRow().Scan()` — error return ถูก assign ให้ blank identifier
- `_, _ = db.Exec(...)` — ทั้ง Result และ error ถูกทิ้ง
- `tx, _ := db.BeginTx(...)` — error จาก Begin ถูกทิ้ง ทำให้ tx อาจเป็น nil

**Expected output:**
```
[RISK: HIGH] pattern: blank identifier  Origin: database/sql
```

---

### 02 `blank_auth` — PatternBlank + crypto/ (HIGH)

**สิ่งที่ทดสอบ:**
- `_, _ = rand.Read(token)` — entropy error ถูกทิ้ง → token bytes เป็น zero
- `key, _ := x509.ParsePKCS1PrivateKey(...)` — parse error ทิ้ง → key = nil
- `ciphertext, _ := rsa.EncryptOAEP(...)` — encryption error ทิ้ง

**Expected output:**
```
[RISK: HIGH] pattern: blank identifier  Origin: crypto/rand
[RISK: HIGH] pattern: blank identifier  Origin: crypto/x509
[RISK: HIGH] pattern: blank identifier  Origin: crypto/rsa
```

---

### 03 `blank_network` — PatternBlank + net/http (HIGH)

**สิ่งที่ทดสอบ:**
- `resp, _ := http.Get(url)` — network error ทิ้ง → resp อาจเป็น nil
- `resp, _ := http.Post(...)` — audit events หายสูญ
- `addrs, _ := net.LookupHost(...)` — DNS failure ทิ้ง

---

### 04 `blank_low_risk` — PatternBlank + fmt/log (LOW)

**สิ่งที่ทดสอบ:**
- `_, _ = fmt.Fprintf(...)` — display error ทิ้ง (OWASP impact = LOW)
- `_ = tmpl.Execute(...)` — template error ทิ้ง
- ยืนยันว่า `slog.Logger.Info()` (ไม่มี error return) ไม่ถูก flag

**Expected output:**
```
[RISK: LOW] pattern: blank identifier  Origin: fmt
[RISK: LOW] pattern: blank identifier  Origin: html/template
```

---

### 05 `check_pattern` — PatternCheck variations

**สิ่งที่ทดสอบ 4 กรณี:**
1. `PropagatedCheck` — `if err != nil { return "", err }` → flow: propagated (correct)
2. `IgnoredErrBranch` — `if err != nil { err = nil }` → flow: discarded (fail-open)
3. `CheckThenContinue` — check แล้ว fall-through → flow: discarded
4. `DoubleCheck` — `errors.Is(err, sql.ErrNoRows)` → flow: propagated

**Key validation:** ErrSec ต้องแยกระหว่าง "checked and returned" กับ "checked but discarded"

---

### 06 `defer_flow` — Smart CFG Defer Routing (FR-04)

**สิ่งที่ทดสอบ:**
- `defer tx.Rollback()` — Smart CFG ต้อง route return edges ผ่าน defer block ก่อน
- `defer func() { _ = rows.Close() }()` — MutationDiscarded อยู่ใน defer closure
- `MultiDefer` — 3 defers ในลำดับ LIFO (C→B→A)

**Key validation:** ถ้า Smart CFG ไม่ redirect edges ถูกต้อง DFA จะมองข้าม defer block

---

### 07 `mutation_wrapped` — MutationWrapped detection

**สิ่งที่ทดสอบ:**
- `fmt.Errorf("...: %w", err)` → MutationWrapped (error ยังคงอยู่, แค่เพิ่ม context)
- wrap chain 2 ชั้น → tracked value เปลี่ยนหลังแต่ละ wrap
- wrap แล้ว discard → flow: wrapped → discarded (ยังถือว่า fail-open)

---

### 08 `mutation_discarded` — MutationDiscarded variations

**สิ่งที่ทดสอบ:**
- `err = nil` inside if-block — explicit nil assignment
- `_ = err` — assign to blank after check
- reassign → nil assign (double-level discard)

---

### 09 `interprocedural` — Function Summary Store (FR-07)

**สิ่งที่ทดสอบ:**
- `helper()` → PropagatesError=true ถูก store ลง SummaryStore
- `helperDiscard()` → DiscardsSomeError=true ถูก store
- `callerOK()` → lookup summary ของ helper() เพื่อ trace cross-function flow
- `callerBad()` → lookup summary ของ helperDiscard()

---

### 10 `complexity_cap` — Safety Cap N=1000 (FR-08)

**สิ่งที่ทดสอบ:**
- `complexFunc()` มี **1002 if-statements** → TooComplex=true
- `simpleFunc()` มี 2 if-statements → วิเคราะห์ปกติ

**Expected output:**
```
UNANALYZABLE FUNCTIONS (jump conditions > 1000)
  [RISK: HIGH] complexity_cap.complexFunc  │  complexity_cap.go:21
```

---

### 11 `multireturn` — Tuple Extraction (FR-03)

**สิ่งที่ทดสอบ:**
- `result, _ := db.Exec(...)` — error element (index=1) ไม่มี referrer
- `_, _ = db.Exec(...)` — ทั้ง 2 elements blank
- `resp, _ := http.Get(...)` — http response captured, error blank
- function ที่ return 3 ค่า (name, age, error) — error ถูก return ถูกต้อง

---

### 12 `mixed` — Combined Realistic Scenario

**สิ่งที่ทดสอบ (6 sites ใน 1 package):**
- `Login()` — DB blank (HIGH) + session check (HIGH) + crypto blank (HIGH)
- `FetchProfile()` — HTTP check then discard (HIGH)
- `AuditLog()` — fmt blank (LOW)
- `DeleteAccount()` — DB check + wrapped return (correct)

**Key validation:** ErrSec ต้องรายงาน sites ทั้งหมดอย่างอิสระโดยไม่ข้ามกัน
