# 프로비저닝 스크립트 (Rune)

프리셋의 `run:` 작업 목록으로 부족할 때, 장비마다 조건에 따라 설정을 정하는 스크립트를 쓴다. 언어는 [Rune](https://rune-rs.github.io/book/)(Rust와 비슷한 동적 언어)이다. 결정 배경은 ADR-060.

## 1. 동작 방식
1. 프리셋 조건(`when`)이 맞으면 스크립트의 `pub fn main(device, args)`가 실행된다(CWMP는 Inform마다, USP는 연결·이벤트마다).
2. 스크립트는 **원하는 상태를 선언**할 뿐 장비에 바로 보내지 않는다(`device.set`).
3. 실행이 끝나면 선언한 값 중 **저장된 값과 다른 것만** 작업이 된다. 그래서 같은 스크립트를 몇 번 실행해도 결과가 같다.
4. 실패(오류, `Err` 반환, 한도 초과)하면 **아무것도 반영하지 않는다**.
5. 무언가 바꾸거나(작업·태그·가상 파라미터) `log`를 남기거나 실패한 실행은 장비 이벤트 `script`로 남는다(UI 장비 상세 → Events): 읽은 값, 선언한 값, `log`, 만든 작업, 태그 변경, 소요 시간, 오류. 아무 일도 없던 실행은 지표 `dhonomos_script_runs_total`로만 센다(주기 Inform마다 도는 스크립트가 이벤트를 쌓지 않도록). 드라이런은 항상 전체 추적을 돌려준다.

## 2. 프리셋에 연결
```yaml
presets:
  - name: wifi-defaults
    when:
      events: ["0 BOOTSTRAP", "1 BOOT"]
      oui: 00AA00
    script: wifi-defaults.rn        # 프리셋 파일과 같은 디렉터리 기준
    args:                           # main의 args (문자열)
      ssid_prefix: Home
```
- `script_source: |`로 스크립트를 YAML 안에 직접 쓸 수도 있다(`script`와 함께 쓰지 않음).
- `run:`과 `script:`를 함께 쓰면 둘 다 적용된다.
- `once: true`는 스크립트와 함께 쓸 수 없다. 스크립트는 선언형이라 매번 실행해도 되므로 `when` 조건으로 범위를 정한다.
- 스크립트는 기동 시 컴파일한다. 문법 오류가 있으면 `dhonomos`가 오류 위치와 함께 기동을 거부한다.
- 고친 뒤에는 `kill -HUP`(compose: `docker compose kill -s HUP dhonomos`)으로 재기동 없이 다시 읽는다. 오류가 있으면 기존 프리셋·스크립트가 계속 쓰인다.

## 3. API
`device`의 속성(읽기 전용): `id`, `serial`(USP는 EndpointID), `oui`, `product_class`, `software_version`, `protocol`(`cwmp`/`usp`).

| 함수 | 설명 |
|---|---|
| `device.get(path)` | 저장된 값(`Some("...")`) 또는 `None`(모름). 장비에 묻지 않는다 |
| `device.list(prefix)` | 객체 경로 아래 저장된 값 `[(path, value), ...]` |
| `device.set(path, value)` | 원하는 값 선언. 문자열·정수·불리언. 타입은 저장된 타입 → 값으로 추정(`boolean`, `int`/`unsignedInt`, `string`) |
| `device.set_typed(path, value, type)` | 타입을 직접 지정(`dateTime` 등) |
| `device.set_virtual(name, value)` | 가상 파라미터 `VirtualParameters.<name>` 계산(7장). 장비로 보내지 않음 |
| `device.refresh(path)` | 값을 다시 읽기(객체 경로는 `.`로 끝남) |
| `device.download(file_id)` | Dhonomos에 올린 펌웨어 파일(ID)로 업그레이드 |
| `device.reboot()` | 다른 작업이 끝난 뒤 재부팅 |
| `device.tag(name)` / `device.untag(name)` | 장비 태그 추가·제거(실행 직후 반영) |
| `device.has_tag(name)`, `device.tags()` | 태그 확인 |
| `device.attribute(key)` | 장비 속성(가입자 번호·요금제 등, 운영 가이드 4b) — `Some("...")` 또는 `None` |
| `device.has_event(code)`, `device.events()` | 이번 Inform의 이벤트(`"1 BOOT"`, `"M Download"` …, 대소문자 무시) |
| `device.log(message)` | 추적에 한 줄(최대 100줄) |

`main`이 `Err("이유")`를 돌려주면 실행이 실패로 기록되고 아무것도 반영되지 않는다.

작업으로 바뀌는 순서: SetParameterValues 1건(선언한 값 전부) → GetParameterValues 1건(refresh) → Download → Reboot.

## 4. 샌드박스
| 한도 | 기본값 | 넘으면 |
|---|---|---|
| VM 명령어 | 1,000,000 | `the script exceeded its instruction budget` |
| 메모리 | 16 MiB | `the script exceeded its memory limit` |
| 파라미터 읽기(`get`·`list`) | 1,000 | `too many parameter reads` |
| 선언(작업·태그) | 1,000 | `too many actions` |

파일·네트워크·시계·출력(`println` 등) 함수는 없다(쓰면 컴파일 오류).

**성능**: 스크립트 실행은 수 µs지만, 실행마다 스크립트에 문자열로 적힌 경로를 DB에서 한 번에 읽는다(경로를 변수로 조립하면 그때마다 추가 조회). 모든 주기 Inform에 매칭되는 스크립트는 최대 처리량을 약 20% 낮춘다(`docs/perf/README.md`) — `when`을 부팅·값 변경 이벤트나 태그·버전으로 좁힌다. 200 ms가 넘는 실행은 경고 로그(`slow provisioning script`)를 남긴다. 지표: `dhonomos_script_runs_total{preset, outcome}`.

## 5. 시험해 보기 (드라이런)
`POST /api/v1/presets/dry-run {"device_id": "...", "events": ["1 BOOT"]}` — 스크립트를 실제 저장값으로 실행하지만 작업·태그·이벤트는 남기지 않는다. 응답의 `items`에 만들어질 작업(`script: true`), `scripts`에 실행 추적이 있다.

## 6. 예제
`deploy/wifi-defaults.rn`:
```rust
pub fn main(device, args) {
    let ssid = "Device.WiFi.SSID.1.SSID";
    match device.get(ssid) {
        None => device.refresh("Device.WiFi.SSID."),
        Some(name) if name == "" => device.set(ssid, `${args["ssid_prefix"]}-${device.serial}`),
        Some(_) => {}
    }
    let guest = device.has_tag(args["guest_tag"]);
    device.set("Device.WiFi.SSID.2.Enable", guest);
}
```

## 7. 가상 파라미터 (CO-06)
(이 장의 예제는 `dhonomos-rules` 테스트 `guide_virtual_parameter_example`로 검증한다.)
제조사마다 경로가 다른 값을 하나의 이름으로 모으거나, 여러 값에서 계산한 값을 장비 파라미터처럼 쓰고 싶을 때 `device.set_virtual(name, value)`를 쓴다.
- 값은 `VirtualParameters.<name>`(이름은 영문·숫자·`_`, 64자 이하)으로 **파라미터 기록에만** 저장된다. 장비로 보내지 않고, 쓰기 불가로 표시돼 설정 백업·복원에서 빠진다.
- 저장된 값과 같으면 다시 쓰지 않는다. 계산 시점은 프리셋 `when` 조건(예: `["1 BOOT", "2 PERIODIC"]`)이 정한다.
- UI 파라미터 탭·API(`/devices/{id}/parameters?prefix=VirtualParameters.`)에서 보이고 다른 스크립트에서 `device.get("VirtualParameters.<name>")`로 읽을 수 있다.

```rust
pub fn main(device, args) {
    // TR-098 / TR-181 어느 쪽이든 WAN 주소를 한 이름으로.
    let wan = match device.get("Device.IP.Interface.1.IPv4Address.1.IPAddress") {
        Some(ip) => Some(ip),
        None => device.get("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress"),
    };
    if let Some(ip) = wan {
        device.set_virtual("wan_ip", ip);
    }
    device.set_virtual("firmware_current", device.software_version == args["firmware"]);
}
```
