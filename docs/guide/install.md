# 설치 가이드 (10분)

Dhonomos는 바이너리 하나(`dhonomos`)와 PostgreSQL 17이 있으면 동작한다. 아래는 Docker Compose로 처음 띄우는 방법이다.

## 1. 준비
- Docker 24 이상(Compose v2 포함), x86_64 리눅스.
- 열 포트: 7547/tcp(CWMP ACS), 7548/tcp(파일 서버: 펌웨어 다운로드·설정 업로드·BulkData). API·웹 UI(8080/tcp)는 TLS가 없으므로 **밖에 열지 않고**, compose는 `127.0.0.1:8080`에만 게시한다(4절의 TLS 리버스 프록시 뒤에서 쓴다). USP를 쓰면 MQTT(외부 브로커 모드의 Mosquitto 1883은 compose가 루프백에만 게시한다. 네트워크의 Agent에는 TLS 8883을 연다. 내장 MQTT 브로커는 TLS 8883), NAT 뒤 CPE를 쓰면 3478/udp(STUN).

## 2. 이미지 만들기
```bash
git clone https://github.com/pdh0085/dhonomos.git && cd dhonomos
docker build -t dhonomos:dev .
```
이미지에는 정적 링크된 `dhonomos` 실행 파일만 들어 있다(기반 이미지 `scratch`, 다른 라이선스의 구성 요소 없음).

릴리스 산출물을 받았다면 먼저 검증한다(서명 → 체크섬, OpenSSH만 필요):
```bash
scripts/verify-release.sh release/allowed_signers ./downloads 0.1.0
docker load < downloads/dhonomos-0.1.0-image.tar.gz
```

## 3. 설정
```bash
cp deploy/dhonomos.env.example deploy/dhonomos.env
openssl rand -base64 32   # 비밀값마다 새로 만들어 넣는다
```
예시 파일의 비밀값은 일부러 비어 있다. 채울 값: `POSTGRES_PASSWORD`, `DHONOMOS_ADMIN_PASSWORD`(10자 이상), `DHONOMOS_FILES_SECRET`(**32바이트 이상**이어야 하고, 바꾸면 기존 링크·STUN 비밀번호가 무효), `DHONOMOS_SECRETS_KEY`(장비 자격증명 암호화), `DHONOMOS_FILES_PUBLIC_URL`(CPE가 파일 서버에 닿는 주소). `DHONOMOS_FILES_SECRET`과 `DHONOMOS_ADMIN_PASSWORD`는 `change-me`·`changeme`·`secret`·`password`나 `change-me`를 포함한 값이면 기동을 거부한다. `--files-secret`이 32바이트보다 짧아도 거부한다: 이 키 하나가 다운로드·업로드·BulkData 링크의 서명과 STUN 비밀번호 유도에 쓰여서, 서명된 링크 하나로 짧은 키를 오프라인에서 추측할 수 있기 때문이다. 파일 서버를 HTTPS로 열려면 `DHONOMOS_FILES_TLS_CERT/KEY`(PEM 파일)를 주고 `DHONOMOS_FILES_PUBLIC_URL`을 `https://`로 쓴다. 인증서 파일을 갱신하면 재기동 없이 반영된다([운영 가이드](operations.md) 4c-1).

## 4. 기동
```bash
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs -f dhonomos   # "API listening"이 보이면 준비 완료
```
브라우저에서 `admin` / `DHONOMOS_ADMIN_PASSWORD`로 로그인한다(서버에서 직접 보려면 `http://127.0.0.1:8080`). Users & keys에서 운영자 계정과 자동화용 API 키를 만든다.

**admin은 2단계 인증이 필수**(기본, ADR-100)라서 첫 로그인 뒤 Account 화면이 열린다. 인증 앱으로 QR을 읽고 코드를 확인한 다음, 나오는 복구 코드 10개를 안전한 곳에 보관한다(자세한 내용과 휴대폰 분실 절차는 [운영 가이드 3c](operations.md#3c-2단계-인증totp)). 이를 위해 `DHONOMOS_SECRETS_KEY`가 필요하다(`deploy/dhonomos.env.example`에 이미 있다). 격리된 실험망에서 끄려면 `DHONOMOS_REQUIRE_ADMIN_TOTP=false`.

### API·웹 UI는 TLS 리버스 프록시 뒤에서
API와 웹 UI에는 자체 TLS가 없다. 로그인 비밀번호와 세션 쿠키가 평문으로 다니지 않게, compose는 8080을 호스트의 `127.0.0.1`에만 게시한다. 다른 곳에서 쓰려면 같은 호스트(또는 신뢰하는 내부망)의 TLS 종단 리버스 프록시(nginx, Caddy, HAProxy 등)를 앞에 두고, `deploy/dhonomos.env`에 `DHONOMOS_SECURE_COOKIES=true`를 준다(세션 쿠키에 `Secure`). 예(Caddy; 인증서는 자동 발급):
```
dhonomos.example.net {
    reverse_proxy 127.0.0.1:8080
}
```
인터넷에 여는 구성(신뢰 프록시 주소, 공개 주소, 2단계 필수 역할, 세션 제한, Apache 예)은 [운영 가이드 2b](operations.md#2b-관리-ui를-인터넷에-열기1단계)에 있다. 루프백이 아닌 주소에서 API를 열었는데 `DHONOMOS_SECURE_COOKIES`가 꺼져 있으면 기동 로그에 `the API listens on a network address without --secure-cookies` 경고가 나온다(컨테이너 안에서는 `[::]:8080`이라 compose에서는 이 경고가 보이면 `DHONOMOS_SECURE_COOKIES=true`를 준다는 뜻이다).

## 5. 첫 CPE 붙이기
ACS는 TLS가 있어야 뜬다: `DHONOMOS_ACS_TLS_CERT/KEY`(PEM 파일)를 주거나, TLS를 종단하는 앞단 프록시 뒤·격리된 실험망에서만 `DHONOMOS_ACS_PLAINTEXT=true`로 평문 HTTP를 허용한다(예시 env에서는 주석 처리돼 있다). CPE의 ACS URL을 `https://<서버>:7547/`(평문을 허용했다면 `http://`)로 설정한다. 첫 Inform이 오면 장비 목록에 나타나고 zero-touch가 전체 파라미터를 읽는다. 장비 인증은 기본이 `DHONOMOS_CPE_AUTH=digest`이고 `DHONOMOS_CPE_USERNAME/PASSWORD`(또는 장비별 자격증명)를 주어야 기동한다. `DHONOMOS_CPE_AUTH=none`은 아무 클라이언트나 아무 CPE 행세를 하게 하므로 격리된 실험망 전용이며, 루프백이 아닌 주소에서는 기동 로그에 `the ACS takes CPEs without authentication` 경고가 나온다.

## 6. USP (선택)
```bash
docker compose -f deploy/docker-compose.yml --profile usp up -d
```
`deploy/dhonomos.env`의 USP 줄 주석을 풀면 Dhonomos가 Mosquitto dynamic-security로 에이전트 계정을 관리한다. 브로커 계정은 둘로 나뉜다: 에이전트 계정을 만들고 ACL을 바꾸는 **관리자**(`dhonomos-admin`, `MQTT_ADMIN_PASSWORD`; Dhonomos는 이것을 dynsec 연결에만 쓴다)와, USP를 구독·발행하기만 하는 **Controller**(`dhonomos-controller`, `MQTT_CONTROLLER_PASSWORD`)다. 둘의 비밀번호는 달라야 하고, 브로커는 첫 기동에 둘을 만든다. 예전 compose로 만든 볼륨(관리자 `dhonomos` 하나가 둘을 겸한다)은 그대로 쓰이며, 나누려면 `mosquitto_ctrl`로 Controller 계정을 따로 만들어 `DHONOMOS_USP_MQTT_USERNAME`/`PASSWORD`를 그것으로 바꾼다. 에이전트마다 API `POST /api/v1/devices`(`endpoint_id`)로 사전 등록 → `POST /api/v1/devices/{id}/mqtt-credentials`로 계정을 받아 에이전트에 넣는다. 응답의 `controller_topic`(`<Controller 토픽>/<EndpointID>`)을 에이전트의 Controller 토픽(`Device.LocalAgent.Controller.{i}.MTP.{i}.MQTT.Topic`)으로 설정한다. 브로커는 에이전트가 자기 토픽에만 쓰게 하므로, Dhonomos는 메시지가 어느 에이전트에서 왔는지 확신할 수 있다(다른 에이전트를 사칭할 수 없다). 공용 토픽으로 보내는 에이전트는 계정이 있어도 메시지가 거부된다.

에이전트가 WebSocket 서버를 여는 경우(예: obuspa `Device.LocalAgent.MTP.{i}.Protocol "WebSocket"`)에는 `DHONOMOS_USP_WS_CLIENTS=true`로 켜고, 사전 등록 때 `"usp_ws_url": "ws://<agent>:<port>/usp"`를 주면 Dhonomos가 접속한다(30초 안에, 끊기면 재접속).

Dhonomos는 Agent가 접속할 때마다 Boot!·OperationComplete·BulkData Push! 구독을 Agent에 넣는다. Agent에 아무것도 쓰지 않게 하려면 `DHONOMOS_USP_AUTO_SUBSCRIBE=false`로 끈다. 그러면 이 알림에 기대는 기능(부팅 시각, `1 BOOT` 프리셋, 비동기 명령 완료)이 동작하지 않으므로 [운영 가이드 4f](operations.md#4f-usp-controller-구독과-데이터-모델-캐시)를 먼저 읽는다.

### WebSocket MTP (Agent가 Dhonomos에 접속)
Agent가 `wss://<서버>:7549/usp?eid=<EndpointID>`(서브프로토콜 `v1.usp`)로 접속한다. 운영은 TLS와 **Agent 클라이언트 인증서 필수**로 켠다.
```bash
DHONOMOS_USP_WS_LISTEN=0.0.0.0:7549
DHONOMOS_USP_WS_TLS=true
DHONOMOS_USP_CA_DIR=/var/lib/dhonomos/usp-ca      # 서버 인증서와 Agent 인증서를 발급하는 USP CA
# DHONOMOS_USP_CA_NAME="Example USP CA"            # 선택: CA 인증서 이름(CN). CA를 처음 만들 때만 쓴다
DHONOMOS_USP_WS_CLIENT_CERT=required              # 운영 권장: none | optional(기본) | required
# 제조사 공장 CA도 신뢰: DHONOMOS_USP_WS_CLIENT_CA=/etc/dhonomos/vendor-ca.pem
```
`DHONOMOS_USP_CA_DIR`을 처음 쓰면 그 디렉터리에 CA(`ca.pem`, `ca.key`)가 만들어진다. CA 인증서의 이름(CN)은 `DHONOMOS_USP_CA_NAME`(`--usp-ca-name`, 최대 64자)이고, 주지 않으면 `Dhonomos USP CA <무작위 8자리 16진수>`다. 이름에 설치마다 다른 접미사가 붙으므로 두 설치가 같은 CA 이름을 갖지 않는다. 이름은 **CA를 만들 때만** 쓴다: 이미 있는 CA는 이름을 바꾸지 않고(다르게 주면 기동 로그에 INFO `the existing USP CA keeps its name`), CA 디렉터리는 **설치 사이에 복사하지 않는다**. 장비에 넣을 클라이언트 인증서는 이 CA가 발급한다([운영 가이드 4d-1](operations.md#4d-1-agent-인증서-발급설치)).

`?eid=`는 Agent가 대는 값일 뿐이다. 클라이언트 인증서가 없으면 아무 클라이언트나 어떤 EndpointID로도 접속해 그 Agent 행세를 할 수 있다(그 Agent에게 나갈 작업을 받고, 복호된 비밀값도 포함된다). 그래서 **운영에서는 `DHONOMOS_USP_WS_CLIENT_CERT=required`를 쓴다.** 기본값 `optional`은 인증서를 내면 그 SAN의 EndpointID와 `?eid=`를 대조하고, 내지 않아도 받는다.

- 루프백이 아닌 주소에서 TLS와 `required`가 아닌 설정으로는 기동을 거부한다(오류에 `--usp-ws-client-cert required`와 `--usp-ws-allow-anonymous`를 안내). 인증서 없는 Agent를 받아야 하는 실험망은 `DHONOMOS_USP_WS_ALLOW_ANONYMOUS=true`를 주면 기동하고, 로그에 `WebSocket MTP takes Agents without a client certificate` 경고를 남긴다. 평문 `ws://`는 루프백(앞단 TLS 프록시 뒤)이 아니면 이 플래그가 있어야만 열린다.
- 인증서 없이 접속한 연결은, 같은 EndpointID로 클라이언트 인증서로 접속한 연결이 열려 있으면 그것을 교체하지 못한다(HTTP 409). 인증서로 접속한 연결은 어떤 연결이든 교체한다(재접속·인증서 갱신). 거절은 `dhonomos_usp_ws_rejected_total`에 센다. 내장 MQTT 브로커와 STOMP도 같은 규칙이다(CONNACK 0x87·ERROR 프레임).
- **인증서가 발급된 EndpointID는 모든 MTP에서 인증서 없는 접속을 거부한다**(WebSocket은 403, STOMP는 ERROR 프레임, MQTT는 CONNACK 0x87 Not authorized). `POST /api/v1/devices/{id}/certificate`로 인증서를 발급(폐기하지 않은 것이 하나라도 있으면 그 EndpointID가 묶인다)하면 Dhonomos가 10초 안에 모든 MTP에 알린다. 그러지 않으면 STOMP·MQTT의 공용 계정(또는 평문 접속)을 가진 쪽이 인증서 장비의 EndpointID를 주장해 약한 MTP로 갈아타게 하고, 그 장비 몫의 작업(복호된 비밀값 포함)을 받을 수 있다. 이미 열려 있는 연결은 끊지 않는다(인증서를 그 연결로 넣는 중일 수 있다). 장비에 인증서를 넣기 전에 끊기면 공용 계정으로는 다시 붙지 못하므로, 인증서를 넣을 준비가 된 뒤에 발급하거나 급하면 그 인증서를 폐기해 풀어 준다(만료는 풀어 주지 않는다: 만료된 인증서도 폐기하기 전까지 그 EndpointID를 인증서에 묶어 둔다).
- **폐기한 인증서**(`POST /api/v1/devices/{id}/certificates/{cert}/revoke`)는 wss·TLS STOMP·TLS 내장 MQTT 어디서든 접속이 거부되고(`the client certificate is revoked`), 그 인증서로 열린 연결은 10초 안에 닫힌다.
- 외부 MQTT 브로커는 이 규칙이 닿지 않는다: TLS를 브로커가 끝내므로 Controller는 클라이언트 인증서를 보지 못한다. 거기서 신원은 브로커의 장비별 계정과 토픽 ACL(위 dynamic-security)이 지킨다. 모든 Agent가 같이 쓰는 Controller 토픽으로 보낸 Record는 보낸 쪽이 누구든 자기 말을 하는 것이라, Controller는 그 주소를 MTP가 신원을 보증한 주소(Dhonomos가 받은 연결, 장비별 토픽)보다 늘 뒤에 둔다.
- `eid`는 MQTT 브로커·STOMP와 같은 규칙으로 검사한다: 비어 있지 않고 256바이트 이하, 공백·제어 문자와 `+` `#` `/`가 없어야 하며, 어긋나면 400.
- Controller가 Agent의 WebSocket 서버에 접속하는 방향(`DHONOMOS_USP_WS_CLIENTS`, 위)은 이 설정과 무관하다.

### 내장 MQTT 브로커 (ADR-093)
외부 브로커 없이 Agent가 Dhonomos에 직접 MQTT 5.0으로 접속한다. 공용 첫 접속 계정과 수용 정책(`--onboarding`, `--allowed-oui`)으로 CWMP처럼 미리 등록하지 않은 장비도 받는다. 외부 브로커 모드와 동시에 켤 수 있다.
```bash
DHONOMOS_USP_MQTT_BROKER_LISTEN=0.0.0.0:1883
DHONOMOS_USP_MQTT_BROKER_USERNAME=cpe
DHONOMOS_USP_MQTT_BROKER_PASSWORD=<공용 비밀번호>
# TLS(8883): DHONOMOS_USP_MQTT_BROKER_LISTEN=0.0.0.0:8883 DHONOMOS_USP_MQTT_BROKER_TLS=true
#   인증서는 wss와 같다(--usp-ws-tls-cert/key 또는 --usp-ca-dir의 USP CA가 발급·갱신)
# 선택: DHONOMOS_USP_MQTT_BROKER_CONTROLLER_TOPIC=usp/controller/dhonomos
#       DHONOMOS_USP_MQTT_BROKER_AGENT_TOPIC_PREFIX=usp/agent/
```
계정 없이 루프백이 아닌 주소에서 열려면 `DHONOMOS_USP_MQTT_BROKER_ALLOW_ANONYMOUS=true`가 있어야 한다(없으면 기동을 거부한다. 실험망 전용). 공용 계정을 두고 TLS 없이 루프백이 아닌 주소에서 열면 계정이 평문으로 다니므로 기동 로그에 `the MQTT broker checks a shared account on a network address without TLS` 경고가 나온다(STOMP 브로커도 같다). 운영은 TLS(8883)와 클라이언트 인증서를 쓴다.

Agent 쪽 설정: Transport MQTT, 호스트·포트, 위 Username/Password, Controller EID(기본 `self::dhonomos-controller`), Controller 토픽 `usp/controller/dhonomos`. **Agent 토픽은 비우거나 `usp/agent/<EndpointID>`로 준다.** 비울 때는 Agent가 CONNECT에 Request Response Information을 넣어야 한다(obuspa: `Device.MQTT.Client.{i}.RequestResponseInfo true`): 브로커가 CONNACK의 Response Information과 `subscribe-topic`으로 Agent의 토픽(`usp/agent/<EndpointID>`)을 알려 주고, Agent는 그것을 구독해 MQTTConnectRecord를 보낸다. 둘 다 아니면 obuspa는 MQTTConnectRecord를 보내지 않아 Dhonomos가 Agent를 알아보지 못한다.

동작 요약:
- Agent의 EndpointID는 TLS 클라이언트 인증서의 SAN → CONNECT의 `usp-endpoint-id` 사용자 속성(TR-369 MQTT 5.0 Agent는 항상 보낸다) → 첫 Record의 `from_id` 순으로 정한다. 공용 계정에서는 `usp-endpoint-id`가 인증되지 않은 주장이므로, 운영에서는 장비 인증서(wss와 같은 USP CA)를 쓴다. 같은 EndpointID의 새 연결은 예전 연결을 DISCONNECT 0x8E로 끊는다 — 같은 EID를 가진 두 장비는 서로를 계속 끊는다.
- Agent는 Controller 토픽(또는 `<Controller 토픽>/<EndpointID>`)에만 쓸 수 있다. 와일드카드·공유 구독, QoS 2, retained 메시지는 거절한다. 메시지는 저장하지 않는다: 접속하지 않은 Agent에게 보내려던 작업은 다음 접속 때 다시 나간다.
- 연결이 끊기면(소켓 종료, Keep Alive의 1.5배 무응답) Controller가 바로 안다. 마지막 접속 시각(`last_contact_at`)은 그 연결에서 마지막으로 받은 시각이다.
- MQTT 3.1.1 클라이언트는 아직 받지 않는다(로드맵 2단계).

obuspa 컨테이너로 확인하기(`deploy/obuspa/factory_reset_mqtt_broker.txt`):
```bash
# 공용 비밀번호가 든 파일은 다른 사용자가 읽지 못하게 만든다(기본 umask로 /tmp에 쓰지 않는다).
d=$(mktemp -d)   # 0700
sed 's/"PASSWORD"/"<공용 비밀번호>"/' deploy/obuspa/factory_reset_mqtt_broker.txt \
  | install -m 600 /dev/stdin "$d/factory_reset.txt"
docker run --rm --network host -v "$d/factory_reset.txt:/etc/obuspa/factory_reset.txt:ro" \
  dhonomos-dev/obuspa:v11.0.7 -p -v4 -r /etc/obuspa/factory_reset.txt -f /tmp/usp.db -i lo
rm -rf "$d"
```
Dhonomos와 같은 호스트에서 `--network host`로 실행하며 파일의 `BrokerAddress`/`BrokerPort`(기본 `127.0.0.1:1883`)를 맞춘다. TLS는 `TransportProtocol "TLS"`, 포트 8883, `-t <USP CA의 ca.pem>`을 더한다. 로그에 `CONNACK`의 `response_information_topic`·`subscribe-topic`, 이어서 Dhonomos 로그에 `agent connected ... reply_to=mqtt:<EndpointID>`가 나오면 된다. 컨테이너를 `docker kill`하면 몇십 밀리초 안에 `agent disconnected (MTP closed)`가 찍힌다.

## 7. WireGuard 허브 (선택, ADR-110)
운영자 PC와 CPE가 WireGuard로 붙는 허브는 별도 프로그램 `dhonomos-wg-hub`가 맡는다. Dhonomos 서버와 같은 호스트에 둬도 되고 다른 호스트에 둬도 된다. 허브에는 도커가 필요 없다. 공인 주소(또는 UDP 포트 포워딩)가 있는 Linux 호스트에 systemd 서비스로 띄운다.

준비할 것:
- Linux kernel의 `wireguard` 모듈, `nft` 프로그램(`nftables` 패키지)
- 허브 호스트에서 Dhonomos API(HTTPS)로 나가는 연결
- 밖에서 허브 UDP 포트(네트워크마다 하나, 51820부터)로 들어오는 연결

1. 서버에서(admin):
   - 허브를 만든다: `POST /api/v1/wireguard/hubs` `{"name": "hub1", "endpoint_host": "<공인 주소 또는 이름>"}`
   - 허브 토큰을 발급한다: `POST /api/v1/wireguard/hubs/{id}/token`. 응답의 `token`은 이때 한 번만 보인다.
   - 네트워크를 만든다: `POST /api/v1/wireguard/networks` `{"hub_id": …, "name": …}`
2. 허브 호스트에서(root):
```bash
install -m 755 dhonomos-wg-hub /usr/local/bin/
install -d -m 700 /etc/dhonomos
install -m 600 /dev/stdin /etc/dhonomos/wg-hub.token   # 토큰을 붙여 넣고 Ctrl-D
install -m 600 deploy/dhonomos-wg-hub.env.example /etc/dhonomos/wg-hub.env   # DHONOMOS_WG_HUB_SERVER를 고친다
install -m 644 deploy/dhonomos-wg-hub.service /etc/systemd/system/
install -m 644 deploy/99-dhonomos-wg-hub.conf /etc/sysctl.d/ && sysctl --system   # net.ipv4.ip_forward=1
echo wireguard > /etc/modules-load.d/wireguard.conf && modprobe wireguard
systemctl daemon-reload && systemctl enable --now dhonomos-wg-hub
```
3. 방화벽:
   - 허브 UDP 포트를 연다. ufw 예: `ufw allow 51820/udp`.
   - 같은 `dwg` interface 안의 중계(forwarding)를 허용한다. 허브의 nft table `inet dhonomos_wg`는 다른 table의 drop을 풀 수 없다. 도커가 깔린 호스트는 FORWARD 기본 정책이 DROP이므로 `iptables -I DOCKER-USER -i dwg+ -o dwg+ -j ACCEPT`가 필요하다. 이 규칙은 재부팅하면 사라지므로 도커 기동 뒤에 다시 넣게 한다.
4. 확인:
   - `journalctl -u dhonomos-wg-hub`에 `hub state received`가 보인다.
   - `GET /api/v1/wireguard/hubs/{id}`에 `public_key`, `last_seen_at`, `version`이 채워진다.
   - `ip link show type wireguard`에 `dwg<포트>`가 보인다.
   - `--dry-run`은 바꿀 것을 출력만 하고 아무것도 바꾸지 않는다. 처음 설치할 때 확인용으로 쓴다.

허브를 멈추거나 서버에 닿지 않아도 커널 상태(터널)는 그대로 남는다. 허브를 영구히 치우려면 `dwg*` 링크, 우선순위 10000의 `iif dwg*` rule, `table inet dhonomos_wg`를 지운다.

## 8. 운영 메모
백업·업그레이드·모니터링·문제 해결은 [운영 가이드](operations.md).

- 상태 확인: `GET /healthz`, 메트릭 `GET /metrics`(viewer 이상).
- 백업: PostgreSQL(`pg_dump`)과 파일 볼륨(`files`)을 함께 백업한다.
- HTTPS 웹훅을 쓰면 호스트 CA 묶음을 마운트한다(compose 예시에 포함).
- 업그레이드: 새 이미지로 교체하면 기동 시 DB 마이그레이션이 자동 적용된다.
- Connection Request 대상 제한: 루프백·링크 로컬(169.254.169.254 메타데이터 포함)·멀티캐스트는 기본 차단. ACS가 있는 서버망 등은 `DHONOMOS_CR_DENY`로 막고, CPE 대역을 알면 `DHONOMOS_CR_ALLOW`로 그 대역만 허용한다.
- 보존 기간: 이벤트 30일, 끝난 작업·해제 알람 90일, 시계열 30일이 기본(`DHONOMOS_*_RETENTION_DAYS`, 0은 무기한).
