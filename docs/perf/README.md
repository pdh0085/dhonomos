# 성능 측정 (Performance)

측정 결과는 하드웨어·커밋과 함께 이 디렉터리에 기록한다. 실행 진입점은 `cargo xtask bench`(Phase 1부터 구현).

## 기준 하드웨어
개발 서버: Intel Xeon E5-2630 @ 2.30GHz, 12 코어, 62 GiB RAM, Ubuntu 24.04 (Linux 6.8).

## 결과

### 2026-10-03 · 스파이크 B — DM XML 파싱 (quick-xml 0.42, release, 5회 중 최소)
`cargo run --release -p dhonomos-datamodel --example spike_parse -- <file>`
객체·파라미터 이름, access, description, syntax 타입을 소유(String) 트리로 구축하는 조건.

| 파일 | 크기 | 파싱 | peak RSS | object / parameter* |
|---|---|---|---|---|
| tr-181-2-21-0-usp-full.xml | 5.6 MB | 25 ms | 12 MiB | 1740 / 8707 |
| tr-181-2-21-0-cwmp-full.xml | 5.1 MB | 23 ms | 11 MiB | 1684 / 8122 |
| tr-098-1-8-0-full.xml | 1.2 MB | 5.4 ms | 4.2 MiB | 427 / 1801 |

목표(< 500 ms, < 200 MiB) 대비 20배 이상 여유. \*profile `ref` 요소를 포함한 대략치이며 정확한 집계는 Phase 1 파서에서.

### 2026-10-03 · Phase 1 — `DataModel::from_xml` 정식 로더 (release, 5회 중 최소)
`cargo run --release -p dhonomos-datamodel --example load_timing -- <file>`
내부 DOM(`xml.rs`) → 타입 모델 2단계. 설명문 정규화, dataType 참조 검증, 커맨드/이벤트 인자·프로파일 포함.

| 파일 | 로드 | peak RSS |
|---|---|---|
| tr-181-2-21-0-usp-full.xml | 74 ms | 44 MiB |
| tr-181-2-21-0-cwmp-full.xml | 68 ms | 41 MiB |
| tr-098-1-8-0-full.xml | 13 ms | 11 MiB |

스파이크(25 ms / 12 MiB) 대비 약 3배 — DOM 중간 단계 비용. 목표 내이므로 단순성을 택함. 서버 기동 시 1회 로드라 추가 최적화 불필요.

### 2026-10-03 · Phase 2 — CWMP 세션 부하 (`cwmp-load`, release)
`cargo run --release -p dhonomos-simulator --bin cwmp-load -- --devices N --rate R --duration S`
가상 CPE가 새 TCP 연결마다 Inform(파라미터 8개) → 빈 POST → (신규 장비면 zero-touch GPV 응답) → 204 세션을 반복.
서버: `dhonomos --cpe-auth none --database-max-connections 32`, PostgreSQL 17(TimescaleDB 이미지, 기본 설정, 같은 호스트).
동시 부하: 24시간 퍼저 3개가 코어 3개 사용 중.

| 시나리오 | 세션/s | 오류 | Inform p50 / p95 / p99 | 세션 p50 / p95 / p99 | dhonomos CPU / RSS |
|---|---|---|---|---|---|
| 장비 2천, 60초 | 100 | 0 | 4.7 / 7.9 / 10.5 ms | 5.7 / 13.0 / 16.6 ms | — |
| 장비 1만, 120초 | 500 | 0 | 6.5 / 12.8 / 51.7 ms | 7.8 / 20.3 / 81.9 ms | 0.8 코어 / 29 MiB |
| 장비 3만(등록 완료), 600초 **(Phase 2 DoD)** | 500 | 0 | 12.9 / 23.7 / 32.7 ms | 14.6 / 25.4 / 35.2 ms | — / 23.5 MiB |
| IPv6(`[::1]` → `[::]` 듀얼스택), 장비 2천, 60초 | 200 | 0 | 4.8 / 7.7 / 9.1 ms | 6.4 / 9.4 / 11.3 ms | — |

Phase 2 DoD(500 Inform/s 10분, p99 < 200 ms) 충족: 30만 세션, 오류 0, 서버 경고 0.

첫 10분 시도는 호스트 디스크가 가득 차(빌드 캐시 `target/` 20 GB) PostgreSQL이 WAL 쓰기에 실패하며 중단됐다. 이후 dev 프로필 디버그 정보 축소, DB 커넥션 대기 5초 제한(장애 시 8005로 빠른 실패) 적용 후 재측정.

PostgreSQL은 500 세션/s에서 합계 약 1.3 코어. 세션당 쓰기: 장비 upsert 1, 파라미터 upsert 1(UNNEST 배치), 이벤트 1, 작업 큐 조회 2.

### 2026-10-04 · Phase 3 — USP Controller 처리량 (`usp-load`, release)
`cargo run --release -p dhonomos-simulator --bin usp-load -- --agents N --concurrency C --duration S`
in-process Controller(`dhonomos-usp-controller`)가 MQTT(dev Mosquitto 2, 같은 호스트)로 N개 가상 Agent에 Get(`Device.DeviceInfo.`)을 동시성 C로 보내고 GetResp를 받는다. Agent도 같은 프로세스(각자 MQTT 클라이언트). DB·작업 큐는 포함하지 않는 Controller+MTP 처리량.

| Agent | 동시성 | 시간 | 요청/s | USP 메시지/s | 오류 | 지연 p50 / p95 / p99 |
|---|---|---|---|---|---|---|
| 200 | 200 | 20초 | 5,089 | 10,177 | 0 | 31.4 / 80.3 / 89.4 ms |
| 1,000 | 500 | 60초 **(Phase 3 DoD: 5,000 msg/s)** | 7,074 | 14,148 | 0 | 71.2 / 80.3 / 84.9 ms |

브로커·Agent·Controller가 한 호스트(퍼저 3코어 사용 중)에서 경쟁하므로 Controller 단독 상한은 더 높다. 작업 큐 경유(DB 포함) USP 처리량은 별도 측정 필요.

### 프로비저닝 스크립트 비용 (2026-10-04, release, ADR-060)
`dhonomos --database-max-connections 96 --acs-max-concurrent 4096` + `cwmp-load --devices 50000 --rate 2000 --concurrency 4000 --event "2 PERIODIC"`(40초, 기준선과 번갈아 2회). 스크립트 프리셋은 **모든 주기 Inform**에 매칭: 값 1개 읽기, 설정 1개 선언(이미 같은 값 → 작업 없음), 가상 파라미터 1개(바뀌지 않음). 호스트에 퍼저 3개가 돌아 기준선도 포화(load avg 9~57).

| 구성 | 세션/s | Inform p50 / p99 |
|---|---|---|
| 기준선(프리셋 없음) | 1,738 / 1,766 | 1,121 / 1,276 ms · 1,100 / 1,290 ms |
| 스크립트, 실행마다 조회 4회(첫 구현) | 1,160~1,321 | 2,592~2,713 ms |
| 스크립트, 리터럴 경로 사전 조회 1회(현재) | 1,342 / 1,354 (−23%) | 1,813 / 2,008 ms · 1,800 / 2,018 ms |

- `Script::run` 자체는 1회 **5.8 µs**(release 마이크로벤치, `run_cost`). 비용은 실행마다 붙는 인덱스 조회 1회(스크립트에 문자열로 적힌 경로를 한 번에 읽음)와 blocking 스레드 전환.
- 권장: 주기 Inform마다 도는 스크립트는 피하고 `when`을 `0 BOOTSTRAP`·`1 BOOT`·`4 VALUE CHANGE`나 태그·버전으로 좁힌다.

### NAT 뒤 UDP Connection Request (2026-10-04, `scripts/nat-test.sh`, ADR-059)
`dhonomos`(debug) WAN 172.31.10.2 ↔ 라우터(MASQUERADE `--random`) ↔ 내부망 CPE(`nat-cpe`). zero-touch로 STUN·장비별 CR 자격증명 수신 → 5초마다 서명된 STUN Binding → 작업 생성 + 깨우기 3회.

| 항목 | 결과 |
|---|---|
| NAT 매핑 | `172.31.20.10:7547` → `172.31.10.254:50104` |
| 깨우기 경로 | 사설 HTTP CR URL → UDP CR(`sent over UDP`) 3/3 |
| 작업 | 3/3 succeeded(UDP CR로 열린 세션에서 실행), 서명 거부 0 |
| 깨우기 → 세션 | 1초 미만 |

## 회귀 게이트 (`cargo xtask bench`, ADR-071)
릴리스 전(`scripts/release.sh`가 실행) 또는 성능에 영향이 있는 변경 뒤에 돌린다. 기준과 비교해 처리량 −10%, p99 +50%, 오류가 있으면 실패한다. 기록은 `docs/perf/bench/history.jsonl`, 기준은 `docs/perf/bench/baseline.json`(`--update-baseline`으로 갱신).

## 향후 측정 항목 (로드맵 참조)
- CWMP Inform 처리량(세션/초), 동시 세션 수
- USP Record 처리량, MQTT 구독 확장
- 디바이스 수별 DB 쓰기 지연

### 2026-10-04 · Phase 3 DoD — 혼합 플릿(CWMP 1,000 + USP 1,000) 동일 프리셋
같은 `dhonomos`(release, `--presets`, `--usp-mqtt-host` dev Mosquitto, `--cpe-auth none`)에 동시에:
- `cwmp-load --devices 1000 --rate 100 --duration 40 --event "0 BOOTSTRAP" --serial-prefix MIX`
- `usp-fleet --agents 1000` (신규 bin: 외부 Controller에 붙는 가상 Agent, Get/Set/Add/GetSupportedDM 응답)

프리셋 하나(`events: ["0 BOOTSTRAP", "USP CONNECT"]`, `once: true`, `Device.DeviceInfo.ProvisioningCode = FLEET-A` 설정).

| 항목 | 결과 |
|---|---|
| 프리셋 작업 | CWMP 1,000/1,000 succeeded, USP 1,000/1,000 succeeded |
| USP 전원 프로비저닝 완료 | 7.9초(접속 → DeviceInfo Get → GSDM → 구독 Add → 프리셋 Set) |
| GSDM 요청 | 1회(같은 펌웨어 1,000대, 지문별 single-flight) → 1,000대 모두 같은 모델에 연결 |
| CWMP 세션 | 4,001회, 오류 0, Inform p50 6.8 / p95 108.5 / p99 1,075 ms, 세션 p99 1,471 ms |
| 서버 경고 | 0 |

CWMP p99가 Phase 2(35 ms)보다 큰 것은 첫 10초에 USP 1,000대 동시 접속(장비 등록·DeviceInfo·구독·프리셋 쓰기)과 CWMP 신규 1,000대 등록이 겹친 결과. 이후 구간은 안정. 접속 폭주 완화(USP 접속 처리 동시성 제한)는 Phase 4 대량 작업 엔진과 함께 검토.
CWMP 시뮬레이터는 상태가 없어 다음 Inform에서 `ProvisioningCode=""`를 보고하므로 스냅샷 값은 덮어써진다(Dhonomos는 SPV 성공 시 스냅샷을 갱신함).

### 2026-10-04 · Phase 4 DoD — 펌웨어 캠페인 1만 대 완주, 카나리 자동 중단
`dhonomos`(release, `--database-max-connections 32`) + `cwmp-load`(상태 있는 가상 CPE: Download → `status 1` → 다음 세션에서 `7 TRANSFER COMPLETE`/`M Download` Inform + TransferComplete, 성공 시 새 SoftwareVersion 보고). 장비는 500 세션/s로 순환(장비당 약 20초마다 세션, CR 없음).

캠페인: 대상 `product_class=FwBox, software_version=[1.0.0]`(1만 대), 작업 `download {file_id}`(서명 URL), 정책 `stages [1,10,100]`, `max_in_flight 3000`, `batch_size 1000`, `abort_failure_rate 5`, `min_samples 20`, `gate_success_rate 95`, `verify 2.0.0 / 600 s`.

| 시각 | 단계 | 상태 |
|---|---|---|
| 0:00 | 1 (1% = 100대) | 100 투입 |
| 0:45 | 2 (10% = 1,000대) | 게이트 통과(100%), 900 투입 |
| 1:30 | 3 (100%) | 게이트 통과, 동시 3,000 상한으로 투입 |
| 3:31 | — | **completed: 10,000/10,000 성공**(작업 성공 + 2.0.0 보고), 서버 경고 0 |

카나리 자동 중단: `FwBad` 2,000대, 다운로드 20% 실패 주입(TransferComplete 9010), 같은 정책.
1단계(20대)는 표본상 실패 1대(5.0%, 임계치 이하·게이트 95% 충족)로 통과, 2단계에서 **실패율 12.2% > 5%로 자동 일시정지**(`failure rate 12.2% exceeded 5% in stage 2 (23 of 188 failed)`). 일시정지 후에도 이미 보낸 작업 결과는 기록되고 큐의 1,800대는 투입되지 않음.

### 2026-10-04 · Phase 4 DoD — 시계열 7일 저장·조회
`bulkdata-load --devices 1000 --days 7`(release): 장비마다 하루치 288개 보고(5분 간격, 지표 10개)를 gzip JSON 한 번에 POST, 동시 32. 수집은 실제 BulkData HTTP 수집기 경유.

| 항목 | 결과 |
|---|---|
| 샘플 | 20,160,000 (POST 7,000, 실패 0, gzip 43.8 MB) |
| 수집 | 64.2초 → **31.4만 샘플/s**, dhonomos RSS 107 MiB |
| 저장 | 2,759 MB(인덱스 포함) = **137 B/샘플** |
| 조회 | 한 장비·한 지표 7일 시간 단위(168점) **p50 10.6 ms**, 최대 11.4 ms |

`device_metrics` 갱신에서 sqlx 느린 쿼리 경고 33건: 생성기가 같은 장비의 7일치를 동시에 보내 행 잠금이 겹친 탓(실제 장비는 순차 보고). 저장 효율은 ADR-037 후속(롤업) 대상.

### 2026-10-04 · USP 펌웨어 캠페인 (FW-05)
`dhonomos`(debug) + `usp-fleet --agents 1000 --run-for 150`(가상 Agent: 슬롯 2개, Download() 비동기 → 1초 뒤 OperationComplete → 재접속 시 새 버전). 잡: `stages [10,100]`, `max_in_flight 500`, `verify 2.0.0`. **1,000/1,000 성공, 약 16초**(상시 연결이라 깨우기 대기 없음).

### 2026-10-04 · 시계열 압축 (ADR-044)
같은 부하(2,016만 샘플)를 `--metrics-raw-days 8`로 원시 저장한 뒤 `--metrics-raw-days 1`로 재기동해 7일을 압축.

| 항목 | 원시 | 압축 후 |
|---|---|---|
| 저장 | 2,755 MB (137 B/샘플) | 131 MB (7.3 B/샘플, 1,795만 샘플) + 오늘 원시 302 MB |
| 압축 시간 | — | 7일 18초(기동 시 1회) |
| 7일 시간 단위 조회 | p50 8.5 ms | 8.5~13.9 ms |

### 2026-10-04 · Phase 5 DoD — 2,000 Inform/s, 5만 CPE
`dhonomos`(release, `--database-max-connections 96 --acs-max-concurrent 4096`, 장비 보고 경로 비동기 커밋 ADR-049) + `cwmp-load --devices 50000 --rate 2000 --concurrency 4000 --event "2 PERIODIC"`. DB는 dev 컨테이너 IP로 직접 접속(docker-proxy 우회 — 포트 매핑 경유 시 docker-proxy가 CPU 183%를 써 병목). 같은 호스트에서 퍼저 3개(코어 3개)와 부하 생성기가 함께 돌았다.

| 시나리오 | 세션/s | 오류 | Inform p50 / p95 / p99 | 세션 p50 / p95 / p99 | dhonomos RSS |
|---|---|---|---|---|---|
| 5만 대 주기 Inform 60초 **(DoD)** | 1,997.7 | 0 | 9.9 / 298 / 441 ms | 17.1 / 584 / 858 ms | **113 MB** |
| 같은 부하, 풀 48·동시 1024(기본) | 1,884.5 | 5.7%(503 부하 차단) | 24.7 / 272 / 331 ms | 46.4 / 558 / 1,403 ms | 114 MB |
| 신규 등록(zero-touch) 600/s, 동기 커밋 | 600 | 0 | 184 / 263 / 292 ms | 622 / 839 / 854 ms | — |
| 신규 등록 600/s, 비동기 커밋 | 600 | 0 | 6.9 / 11.0 / 13.8 ms | 20.6 / 33.6 / 40.3 ms | — |

5만 CPE 메모리 113 MB(DoD 4 GiB 미만).

신규 등록(zero-touch: 장비 INSERT + GPV + GPN) 1,000/s 요청 시(풀 96·동시 4096): 오류 0, 처리 **약 675 등록/s**에서 포화(Inform p50 1.5 s). 시간당 240만 대 신규 등록에 해당해 중규모 ISP(전체 수만 대)에는 여유. 개선 여지: Inform 처리 쿼리를 한 트랜잭션으로 묶기.
