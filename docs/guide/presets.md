# 프리셋과 작업 레퍼런스

프리셋(preset)은 장비가 접속할 때(CWMP Inform, USP 연결·이벤트) 조건이 맞으면 작업(task)을 큐에 넣는 규칙이다. 예제: `deploy/presets.example.yaml`.

**어디에 두나** (ADR-077)
- **DB(기본)**: `--presets` 없이 띄우면 프리셋은 PostgreSQL에 있고 UI **Presets**나 API로 만들고 고친다.
  - 저장 전에 검증(스크립트 컴파일)한다.
  - 저장할 때마다 리비전이 올라가고 이력이 남는다. 고치는 사이 다른 사람이 저장했으면 409로 막힌다.
  - 모든 프로세스가 5초 안에 반영한다.
  - 편집기의 **Test this preset**은 저장하지 않은 초안을 장비 하나에 드라이런한다.
- **파일**: `--presets <file>`이면 지금처럼 YAML 파일에서 읽고, 고친 뒤 `kill -HUP`으로 다시 읽는다([운영 가이드](operations.md) 4a). UI는 읽기 전용이다. Git으로 관리(GitOps)하려면 이쪽을 쓴다.
- **옮기기**: 파일 → DB는 UI **Import YAML**이나 `POST /api/v1/presets/import {"yaml": "..."}`(`dry_run`으로 먼저 확인)로 한다. 스크립트 파일(`script:`)은 `script_source:`에 내용을 넣어야 한다. DB → 파일은 **Export YAML**(`GET /api/v1/presets/export.yaml`)로 한다.
- **API**:

  | 요청 | 하는 일 |
  |---|---|
  | `GET /api/v1/presets/{name}` | 프리셋 하나 |
  | `PUT /api/v1/presets/{name} {"definition": {...}, "revision": N}` | 저장. 새로 만들 때는 `revision: 0` |
  | `DELETE ...?revision=N` | 삭제(이력에는 남는다) |
  | `GET .../history` | 리비전 이력 |
  | `POST /api/v1/presets/validate` | 저장하지 않고 검증만 |
- **권한**: 프리셋 변경은 operator 이상이면서 장비 범위가 없는 계정만 할 수 있다(프리셋은 모든 장비에 적용되므로).
- **이름**: 한번 정하면 바꿀 수 없다. `once` 프리셋은 이름으로 실행 여부를 기억하기 때문이다.
- **비밀**(ADR-096): DB의 프리셋에서 작업의 `password`와 `secret: true`인 `values[]` 값은 **쓰기 전용**이다.
  - 저장하면 암호화하고(`--secrets-key` 필요, 없으면 422) 목록·단건·이력·내보내기·드라이런·감사 기록 어디에도 보이지 않는다 — `********`로 나온다.
  - 고칠 때 `********`를 그대로 보내면 **같은 작업(`run` 순서)의 같은 칸에 저장된 값을 유지**한다. 값을 바꾸려면 새 값을 보낸다. 저장된 값이 없는 칸에 `********`를 보내면 422다(새 프리셋 가져오기 포함). 작업 순서를 바꾸면 칸이 달라지므로 비밀을 다시 넣어야 한다.
  - 내보낸 YAML에는 `********`가 들어 있다. 기존 프리셋에 가져오면 비밀이 유지되고, 새 프리셋이나 `--presets` 파일로는 쓸 수 없다(비밀을 써 넣어야 한다).
  - "이 판으로 되돌리기"는 비밀을 되돌리지 않는다(이력에는 비밀이 없다). 현재 저장된 값이 유지된다.
  - 파일 프리셋(`--presets`)은 파일에 쓴 대로(평문)이다. 스크립트의 `args`·`set()` 값은 비밀 칸이 아니다 — 스크립트에 비밀을 넣지 않는다.

## 1. 프리셋
```yaml
presets:
  - name: periodic-inform          # 고유 이름(작업의 멱등 키에 들어감)
    when:                          # 모든 조건을 만족해야 함(빠진 조건은 무시)
      events: ["0 BOOTSTRAP"]
    once: true                     # 장비당 한 번만(기본: 조건이 맞을 때마다)
    priority: 0                    # 큐 우선순위(클수록 먼저)
    run:                           # 작업 목록(API의 작업과 같은 형식, 3장)
      - kind: set_parameter_values
        payload:
          values:
            - { name: Device.ManagementServer.PeriodicInformInterval, value: "3600", type: unsignedInt }
```

| 키 | 뜻 |
|---|---|
| `name` | 고유 이름 |
| `enabled` | `false`면 남겨 두되 실행하지 않음(기본 `true`) |
| `when.events` | 이벤트 코드 중 하나라도(`"0 BOOTSTRAP"`, `"1 BOOT"`, `"2 PERIODIC"`, `"4 VALUE CHANGE"`, `"6 CONNECTION REQUEST"`, `"M Download"` …). USP는 `"USP CONNECT"`(연결), `"1 BOOT"`(Boot!) |
| `when.oui` | 제조사 OUI(대소문자 무시) |
| `when.product_class` | 제품군(정확히 일치) |
| `when.software_version` | 펌웨어 버전 전체에 맞는 정규식(예: `"2\\..*"`) |
| `when.tags` | 이 태그를 모두 가진 장비 |
| `when.new_device` | `true`면 처음 본 장비만, `false`면 아는 장비만 |
| `when.attributes` | 장비 속성 값이 정확히 같은 장비(예: `{ plan: gold }`, 가입자 연결) |
| `once` | 장비당 한 번. 스크립트와는 함께 쓰지 않음 |
| `priority` | 큐 우선순위 |
| `run` | 작업 목록 |
| `script` / `script_source` / `args` | Rune 스크립트([스크립트 가이드](scripts.md)) |

**중복 방지**: 같은 프리셋이 같은 접속에서 두 번 큐에 넣지 않는다(CWMP는 Inform의 `CurrentTime`, USP는 연결마다). `once`는 장비마다 한 번(작업 기록이 보존 기간 정리에서 빠짐).

**드라이런**: UI Presets → Dry run, 또는 `POST /api/v1/presets/dry-run {"device_id": "...", "events": ["1 BOOT"]}` — 무엇이 큐에 들어갈지(스크립트는 실제로 실행해 추적까지) 보여 주고 아무것도 바꾸지 않는다.

## 2. 작업이 실행되는 방식
- CWMP: 장비가 다음에 접속한 세션에서 우선순위 순으로 실행. 바로 실행하려면 Connection Request(작업 생성 시 `connection_request: true`).
- USP: Agent가 연결돼 있으면 바로, 아니면 다음 연결 때.
- 실패한 작업은 다시 시도할 만한 오류(9001·9002·9004·9010·9011·9014–9017·9020, 연결 끊김)면 최대 3번 재시도하고, 그 밖의 오류는 바로 실패로 끝난다.
- 결과는 UI 장비 → Tasks, `GET /api/v1/tasks/{id}`.

## 3. 작업 종류
API(`POST /api/v1/devices/{id}/tasks`), 잡(대량 작업), 프리셋 `run`에서 같은 형식을 쓴다: `{"kind": "...", "payload": {...}}`. USP 열이 `—`인 작업을 USP 장비에 보내면 실패로 끝난다.

| kind | payload | CWMP | USP |
|---|---|---|---|
| `get_parameter_values` | `names: [경로]`(`.`로 끝나면 하위 전체) | GetParameterValues | Get |
| `set_parameter_values` | `values: [{name, value, type?, secret?}]` — `type`은 `string`(기본)·`boolean`·`unsignedInt`·`int`·`dateTime` 등, `secret: true`면 암호화 저장·스냅샷 제외 | SetParameterValues | Set |
| `get_parameter_names` | `path`, `next_level?` | GetParameterNames | — (USP는 지원 모델 캐시를 씀) |
| `get_parameter_attributes` | `names` | GetParameterAttributes | — |
| `set_parameter_attributes` | `changes: [{name, notification}]` — 0 끔, 1 수동, 2 능동(값 변경 알림) | SetParameterAttributes | — (USP는 구독) |
| `add_object` | `object`(예: `Device.NAT.PortMapping.`) | AddObject | Add |
| `delete_object` | `object`(예: `Device.NAT.PortMapping.3.`) | DeleteObject | Delete |
| `reboot` | — | Reboot | `Device.Reboot()` |
| `factory_reset` | — | FactoryReset | `Device.FactoryReset()` |
| `download` | `file_id`(Dhonomos에 올린 파일) 또는 `url`, `file_type?`(기본은 파일의 종류, 예: `"1 Firmware Upgrade Image"`, `"3 Vendor Configuration File"`), `username?`/`password?`(외부 서버), `sha256?`(소문자 16진수 64자, `file_id`면 저장된 값으로 자동), `delay_seconds?` | Download → TransferComplete(sha256은 쓰지 않음) | 펌웨어: 비활성 슬롯 `FirmwareImage.{i}.Download()`(+ `CheckSumAlgorithm=SHA-256`·`CheckSum`), 설정 파일: `VendorConfigFile.{i}.Restore()`(체크섬 동일) |
| `upload` | `file_type`(`"1 Vendor Configuration File"`, `"2 Vendor Log File"`), `url` | Upload | `VendorConfigFile.{i}.Backup()` / `VendorLogFile.{i}.Upload()` |
| `diagnostic` | `test`(`ip_ping`·`trace_route`·`ns_lookup`·`download`·`upload`·`wifi_neighbors`), `params`(중립 입력; `download`·`upload`에서 `url`을 빼면 Dhonomos 파일 서버가 시험 서버) | 객체 설정 + `8 DIAGNOSTICS COMPLETE` 후 결과 읽기 | 진단 명령(Operate) |
| `operate` | `command`(`()`로 끝남), `input: {이름: 값}` | — | Operate |

설정 파일 백업은 보통 API `POST /api/v1/devices/{id}/config-files`(업로드 URL을 알아서 만듦)로, 펌웨어 교체는 잡(캠페인)으로 하는 것이 편하다.
