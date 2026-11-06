# 장비 필터 표현식

장비 목록(UI 검색창 아래 칸, `GET /api/v1/devices?filter=`), CSV 내보내기(`/devices/export.csv?filter=`), 잡 대상(`target.expression`)에서 조건을 조합해 장비를 고른다(NB-01, ADR-079).

```text
product_class = "HG8245" and (tag = east or attr.region = busan) and last_contact > 1d
param."Device.DeviceInfo.UpTime" < 600 and not tag = lab
version !~ beta and attr.subscriber exists
xmpp_connected = false and udp_cr = false and protocol = cwmp
```

## 문법
- 조합: `and`, `or`, `not`, 괄호. `and`가 `or`보다 먼저 묶인다(`a or b and c` = `a or (b and c)`).
- 값: 공백·특수문자가 없으면 그대로(`east`), 있으면 따옴표(`"Home WiFi"`, `'x'`). 따옴표 안에서 `\"`는 따옴표 문자 그대로.
- 대소문자: 키워드(`and`·`or`·`not`·`exists`)와 필드 이름은 구분하지 않는다. `=` 비교는 구분하고 `~`는 구분하지 않는다.

| 연산자 | 뜻 |
|---|---|
| `=` `!=` | 같음 / 다름(값이 없어도 "다름") |
| `~` `!~` | 포함 / 포함하지 않음(대소문자 무시) |
| `<` `<=` `>` `>=` | 파라미터는 숫자 비교, 시간 필드는 **경과 시간** 비교 |
| `exists` | 값이 있음(`attr.plan exists`, `param."Device.X" exists`). 반대는 `not ... exists` |

## 필드
| 필드 | 대상 |
|---|---|
| `serial`, `endpoint_id`, `oui`, `product_class`, `manufacturer`, `model`, `version`(=`software_version`), `hardware_version`, `protocol`, `status`, `address`, `data_model` | 장비 정보 |
| `tag` | 태그 하나(`tag = east`: east 태그가 있음) |
| `attr.<키>` | 속성(CO-13). `=`은 색인을 탄다 |
| `param.<경로>` 또는 `param."<경로>"` | 저장된 파라미터 값(마지막으로 읽은 값). 숫자 비교는 값이 숫자일 때만 맞는다 |
| `xmpp_connected`, `udp_cr` | 참/거짓 필드: `= true`, `= false`(`!=`도 된다), `exists`(= `= true`). `xmpp_connected`는 장비에 지금 XMPP 세션이 있음(`xmpp_connected_at`이 있음, ADR-104), `udp_cr`는 UDP Connection Request 주소를 앎(`udp_cr_address`, ADR-040). 그 밖의 연산자와 `true`·`false` 외의 값은 오류다 |
| `last_contact`, `last_boot`, `first_seen` | 경과 시간: `last_contact < 15m`(15분 안에 접속), `last_contact > 1d`(하루 넘게 없음, 한 번도 없으면 포함). 단위 `s`·`m`·`h`·`d`·`w` |

**USP 장비의 `last_contact`**: Agent가 접속해 있는 동안 Dhonomos가 그 연결에서 **마지막으로 받은 것**의 시각이다(접속 중이라고 지금 시각으로 올리지 않는다). WebSocket은 어떤 프레임이든(서버가 30초마다 보내는 Ping에 대한 Pong 포함), STOMP는 프레임·하트비트 줄이든 무엇이든 받은 시각이고, Linux에서는 STOMP 연결의 TCP 확인응답(ACK, TCP keepalive 포함)도 센다. 전원이 끊긴 장비는 연결이 끊겼다고 판정되기까지(wss 90~120초) 시간이 걸리지만, `last_contact`는 그 사이에 늘지 않고 마지막으로 받은 시각에 멈춘다. 외부 MQTT 브로커 뒤의 Agent는 연결을 Dhonomos가 직접 보지 못하므로, 접속 중인 동안 1분마다 지금 시각으로 올린다.

## 쓰는 곳
- **장비 목록**: 다른 검색 조건(검색어, 프로토콜, 상태, 속성 칸)과 AND로 합쳐진다. 범위 사용자는 자기 범위 안에서만 찾는다.
- **CSV 내보내기**: 목록과 같은 조건으로 내보낸다.
- **잡 대상**: 고정 조건(제품군, 태그 등)과 AND로 합쳐진다. 미리보기와 잡 시작 시점에 대상 장비가 정해지고, 이후 조건이 바뀌어도 잡 멤버는 그대로다.
- **알람 규칙·사일런스**: 표현식을 쓸 수 없다. 1분마다 평가하는 고정 쿼리이므로 고정 조건(`product_class`, `tags`, `attributes` 등)만 받는다.

## 제한
- 길이 2,000자, 조건 50개, 중첩 20단계.
- 오류 위치를 알려 준다. 예: `filter, at character 24: expected a condition`.
- 필드 이름은 정해진 목록에서만 받고, 값은 모두 SQL 매개변수로 넘긴다(SQL 주입 불가).
- 성능(장비 14만 대, release 빌드):

  | 조건 | 걸린 시간 |
  |---|---|
  | 제품군·속성·태그 | 0.06–0.14초 |
  | 부분 일치 | 0.14초 |
  | 전체 장비의 파라미터 숫자 비교 | 0.5초 |
