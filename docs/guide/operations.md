# 운영 가이드

설치는 [install.md](install.md). 이 문서는 띄운 뒤의 일: 구성, 백업·복구, 업그레이드, 보존, 모니터링, 문제 해결.

## 1. 프로세스 구성
`dhonomos` 하나가 모든 서비스를 돌린다(`--role all`, 기본). 나눌 때:

| 역할 | 하는 일 | 몇 개 |
|---|---|---|
| `--role acs` | CWMP 리스너(7547), 파일 서버(7548), STUN, USP Controller | 부하에 따라 여러 개(같은 DB) |
| `--role api` | API·웹 UI(8080) | 1개 이상 |

- 모든 프로세스가 공통으로 작업 엔진(잡)·보존 정리·시계열 파티션 관리를 돌린다. 잡은 DB 잠금으로 한 프로세스만 진행한다(연결이 끊기면 잠금을 놓고 다른 프로세스가 이어받음).
- 알람 엔진도 DB 잠금으로 한 프로세스만 평가한다(`alarm engine active` 로그). 잠금을 쥔 프로세스가 죽거나 DB 연결이 끊기면 다른 프로세스가 이어받는다. `--alarms`·웹훅 설정은 모든 프로세스에 같게 준다.
- USP Controller는 Controller 토픽을 일반 구독하므로 둘이면 Agent 메시지를 둘 다 받는다. **USP를 켠 프로세스는 하나**로 둔다(수평 확장은 로드맵 OP-03).
- 내장 XMPP 서버(`--xmpp-listen`, 4h)의 장비 연결은 그 프로세스의 메모리에 있다. **XMPP 서버와 깨우기(API·잡)는 같은 프로세스**여야 하므로 `--role all`로 돌린다. 한 프로세스만 XMPP를 켠다.

## 2. 꼭 지켜야 할 비밀값
| 값 | 바뀌면 |
|---|---|
| `--secrets-key`(`DHONOMOS_SECRETS_KEY`) | 그냥 바꾸면 저장된 장비 자격증명·작업 비밀번호·운영자의 2단계 인증 비밀을 **복호화할 수 없다**(아래 회전 절차로 바꾼다). 백업과 별도로 안전하게 보관 |
| `--files-secret` | 발급된 다운로드·업로드·BulkData 링크가 무효, **STUN 비밀번호가 바뀌어** NAT 뒤 장비의 UDP CR이 다음 프로비저닝까지 실패 |
| `--usp-ca-dir`의 CA 키 | 발급한 Agent 인증서 검증 불가 → 모든 wss Agent 재발급. 이 디렉터리를 다른 설치에 복사하지 않는다([4d-1](#4d-1-agent-인증서-발급설치)) |
| 릴리스 서명 키 | ADR-056 사용자 보관 |

**비밀값 키 회전**(`--secrets-key`, ADR-082):
1. 새 키를 만든다: `openssl rand -base64 32`.
2. 모든 프로세스를 이렇게 바꿔 띄운다.

   | 설정 | 값 |
   |---|---|
   | `DHONOMOS_SECRETS_KEY` | 새 키 |
   | `DHONOMOS_SECRETS_KEY_ID` | 새 이름(예: `k2`) |
   | `DHONOMOS_SECRETS_OLD_KEYS` | 이전 키(여러 개면 쉼표로 구분) |
3. 기동 로그에 `secrets re-encrypted; nothing is left under the old keys`가 나오면 끝이다. 장비 자격증명, 운영자의 2단계 인증 비밀, 아직 끝나지 않은 작업·잡의 비밀번호, 저장된 프리셋의 비밀이 새 키로 다시 암호화된다. 끝난 작업의 비밀번호는 다시 쓰지 않으므로 그대로 둔다.
4. `DHONOMOS_SECRETS_OLD_KEYS`를 지우고 다시 띄운 뒤, 이전 키를 폐기한다.
- 로그에 `unreadable`이 나오면 어떤 키로도 열리지 않는 비밀값이 있다는 뜻이다(잃어버린 키). 그 자격증명은 다시 발급해야 한다.

## 3. 백업과 복구
백업 대상은 셋: **PostgreSQL**, **파일 저장소**(`--files-dir`), **비밀값**(위 표, 환경 파일).

```bash
# 온라인 백업 (dhonomos를 멈출 필요 없음)
docker compose exec -T postgres pg_dump -U dhonomos -Fc dhonomos > dhonomos-$(date +%F).dump
docker run --rm -v dhonomos_files:/f -v "$PWD":/b alpine tar czf /b/files-$(date +%F).tar.gz -C /f .
```

- 시계열(`metric_samples_*` 파티션)이 DB의 대부분이다. 백업 크기를 줄이려면 `pg_dump --exclude-table-data='metric_samples_*'`(롤업 `metric_rollups`는 남김).
- 장비 보고 경로는 비동기 커밋이라(ADR-049) DB 장애 시 마지막 1초 미만의 장비 보고가 사라질 수 있다. 장비가 다음 세션에 다시 보고하므로 복구 후 따로 할 일은 없다.

복구:
```bash
docker compose stop dhonomos
docker compose exec -T postgres pg_restore -U dhonomos -d dhonomos --clean --if-exists < dhonomos-2026-10-04.dump
docker run --rm -v dhonomos_files:/f -v "$PWD":/b alpine sh -c 'rm -rf /f/* && tar xzf /b/files-2026-10-04.tar.gz -C /f'
docker compose start dhonomos   # 같은 비밀값(env 파일)으로
```

## 4. 업그레이드
1. 백업(3장).
2. 새 이미지로 교체: `docker compose pull && docker compose up -d`(직접 빌드했다면 `docker build` 후 `up -d`).
3. 기동 시 DB 마이그레이션이 자동 적용된다(`database ready` 로그). 마이그레이션은 앞으로만 간다 — 되돌리려면 백업으로 복구.
4. 여러 프로세스면 API 먼저, ACS를 하나씩 교체한다. CPE는 끊긴 세션을 다음 주기에 다시 시작한다.

## 2a. 보안 기본값
- 계정이나 `--api-token` 없이 외부 주소에 API를 열면 기동을 거부한다(누구나 관리자가 되므로). 격리된 실험망에서만 `--api-allow-open`을 쓴다.
- HTTPS로 서비스하면 `--secure-cookies`를 켠다(세션 쿠키가 `Secure`가 되고 이름에 `__Host-` 접두사가 붙는다 — 켜는 순간 이전 세션은 끝나므로 한 번 다시 로그인한다). 역방향 프록시는 `Host`를 그대로 넘기거나(`ProxyPreserveHost On`), `--trusted-proxies`로 프록시를 지정해 그 프록시의 `X-Forwarded-Host`를 쓰게 하거나, `--public-url`로 주소를 못박는다. 브라우저의 변경 요청은 Origin이 이 주소와 같아야 받아들인다. **프록시가 `Host`를 바꾸면서 `--trusted-proxies`·`--public-url`이 없으면 변경 요청이 403**이다(10-14 변경: 아무나 쓸 수 있는 `X-Forwarded-Host`는 더 이상 믿지 않는다).
- 계정도 토큰도 없는 "열린 모드"(누구나 admin)는 **프록시를 거친 요청에는 절대 주지 않는다**(`Forwarded`·`X-Forwarded-*`·`X-Real-IP` 헤더가 있거나 `--trusted-proxies`의 프록시에서 온 요청은 401 `no accounts exist; create an admin account on the server`). 계정이 없고 토큰도 없으면 기동 로그에 WARN이 난다. 인터넷에 열기 전에 admin 계정을 만든다([2b](#2b-관리-ui를-인터넷에-열기1단계)).
- **admin은 2단계 인증(TOTP)이 필수**다(`--require-totp-roles`, 기본 `admin`; `--require-admin-totp`도 계속 동작; [3c](#3c-2단계-인증totp)). 이를 위해 `--secrets-key`가 있어야 하며, 없으면 기동을 거부한다. 끄려면 `--require-totp-roles none`(또는 `--require-admin-totp false`).
- 인터넷에 여는 방법과 점검: [2b](#2b-관리-ui를-인터넷에-열기1단계).
- USP over MQTT는 dynamic-security(`--usp-dynsec`)로 Agent별 계정을 쓴다. Agent는 발급 응답의 `controller_topic`(Agent별 토픽)으로 보내야 하며, 그래야 다른 Agent를 사칭할 수 없다.

## 2b. 관리 UI를 인터넷에 열기(1단계)
웹 UI·API(8080)**만** 인터넷에서 닿게 하는 구성이다(ADR-103). 자체 TLS가 없으므로 같은 호스트의 TLS 리버스 프록시(아래는 Apache)가 `127.0.0.1:8080`으로 넘긴다. **장비 쪽 포트는 열지 않는다**: ACS 7547·파일 서버 7548·USP WebSocket 7549·STOMP 61614·MQTT 8883(·1883)은 장비망 주소(예 `10.20.30.1`)에만 바인드하거나 방화벽(ufw)으로 막고, 밖에서 `nmap -Pn -p 22,80,443,1883,7547-7549,8080,8883,61614 <공인 주소>`로 443(과 SSH 등 의도한 것)만 열려 있는지 확인한다. 가장 안전한 방법은 공개하지 않고 VPN으로만 쓰는 것이다.

### 1. 먼저 할 일 (프록시를 켜기 전에)
1. **admin 계정을 만든다.** 계정이 없으면 서버가 열린 모드이므로 프록시가 붙으면 안 된다. 첫 기동에 `DHONOMOS_ADMIN_PASSWORD`를 주면 계정 `admin`이 생긴다(무작위 비밀번호: `openssl rand -base64 18`). 이름 `admin`은 누구나 아는 이름이므로(로그인 잠금은 이름·클라이언트 주소별이라 한 사람이 남을 잠글 수는 없지만 추측 대상이 된다) UI Settings → 사용자에서 **예측하기 어려운 이름**의 admin을 새로 만들어 로그인하고 `admin`은 비활성화한다. 그 뒤 `DHONOMOS_ADMIN_PASSWORD`는 env에서 지운다. 프록시를 켠 뒤에는 서버 안에서 직접 부른 요청(127.0.0.1)도 `--trusted-proxies` 때문에 "프록시를 거친 요청"이 되어 열린 모드가 없으므로, 첫 계정은 반드시 이 단계에서 만든다.
2. **그 admin에 2단계 인증(TOTP)을 등록한다**(Account 화면, [3c](#3c-2단계-인증totp)). 복구 코드는 안전한 곳에. 다른 admin을 하나 더 두어 한쪽이 휴대폰을 잃어도 초기화할 수 있게 한다.
3. **`--api-token`(`DHONOMOS_API_TOKEN`)은 설정하지 않는다.** 만료 없는 admin 자격증명이고, 브라우저 저장소에 붙여 넣게 된다. 기계용은 만료·폐기가 되는 API 키(역할을 최소로)를 쓴다.

### 2. 서버 설정
```
DHONOMOS_SECURE_COOKIES=true            # 세션 쿠키: Secure + __Host- 접두사 (켜면 한 번 다시 로그인)
DHONOMOS_TRUSTED_PROXIES=127.0.0.1/32   # 프록시의 주소. 이 주소에서 온 X-Forwarded-For만 믿는다
DHONOMOS_PUBLIC_URL=https://rms.example.org
DHONOMOS_REQUIRE_TOTP_ROLES=admin,operator
DHONOMOS_SESSION_HOURS=8                # 세션 최대 수명 (기본 12)
DHONOMOS_SESSION_IDLE_MINUTES=30        # 쓰지 않으면 끝나는 시간 (기본 60, 0 = 끔)
```
| 설정 | 하는 일 |
|---|---|
| `--trusted-proxies` | 쉼표로 구분한 네트워크(기본 비어 있음). TCP 연결이 이 안에서 오면 클라이언트 주소는 `X-Forwarded-For`(없으면 RFC 7239 `Forwarded: for=`)에서 **오른쪽부터 보아 이 목록에 없는 첫 주소**다. 왼쪽에 방문자가 써 넣은 값은 무시된다. 이 목록 밖에서 온 요청의 전달 헤더는 모두 무시한다. 두 헤더가 다른 주소를 가리키면 둘 다 믿지 않고 프록시 주소를 쓴다. **공격자가 닿을 수 있는 대역을 넣지 않는다**(`0.0.0.0/0`이면 기동 시 경고). 이 주소로 공개 경로 속도 제한(초당 2회, 버스트 30)·인증 실패 제한·SSO 진행 상한(주소당 20)·로그인 잠금·로그가 방문자별로 따로 돈다. 비워 두면 프록시 뒤의 모든 방문자가 프록시 한 주소로 보여 한 사람이 모두의 로그인을 막을 수 있다(`--public-url`만 있고 이 값이 없으면 경고). Docker라면 컨테이너가 보는 연결 상대는 브릿지 게이트웨이(예 `172.18.0.1`)이므로 `docker network inspect`로 확인한 그 네트워크를 넣는다. |
| `--public-url` | UI의 공개 주소(`https://호스트[:포트]`, 경로 없음). 브라우저의 변경 요청은 `Origin`이 **스킴·호스트·포트까지 정확히** 이 주소일 때만 받는다(`Host`·`X-Forwarded-Host`는 보지 않는다). 비어 있으면 `Origin`의 호스트가 `Host`(또는 신뢰 프록시의 `X-Forwarded-Host`)와 같고, 신뢰 프록시가 `X-Forwarded-Proto`로 스킴을 알려 주면 그와 같아야 한다. |
| `--secure-cookies` | 세션 쿠키 `__Host-dhonomos_session`(Secure, Path=/, Domain 없음). 이 이름을 쓰는 동안 옛 이름(`dhonomos_session`)은 세션으로 읽지 않는다(형제 도메인이 심은 쿠키로 세션을 고정하지 못하게). 신뢰 프록시가 `X-Forwarded-Proto: https`를 보냈는데 이 옵션이 꺼져 있으면 쿠키는 `Secure`로 나가지만 접두사는 없고, 경고가 로그에 10분에 한 번 나온다. 기동 때 신뢰 프록시나 https 공개 주소가 있는데 이 옵션이 꺼져 있으면 경고한다. |
| `--require-totp-roles` | 2단계 인증을 **반드시** 써야 하는 역할(`admin,operator,viewer` 중 쉼표로; `none` = 없음; 기본 `admin`). 이 역할의 계정이 비밀번호로 로그인했는데 2단계가 없으면 세션은 **등록 전용**이다(나머지 API는 403 `two-factor enrollment required`). 목록에 든 역할은 2단계를 끌 수도 없다. 점검 X-6: operator는 전체 장비에 공장 초기화·펌웨어 배포 잡을 낼 수 있으므로 인터넷에 열 때는 `admin,operator`. API 키·`--api-token`·SSO는 해당 없음. 옛 `--require-admin-totp`는 그대로 동작한다: 명시하면 `true`는 admin을 목록에 더하고 `false`는 목록에서 뺀다(명시하지 않으면 목록만 본다). |
| `--session-idle-minutes` | 이 시간 동안 쓰지 않은 세션은 끝난다(기본 60, 0 = 끔). 마지막 사용 시각은 분당 한 번만 갱신해 쓰기 부담이 없고, 열려 있는 실시간 스트림(SSE)은 유휴로 세지 않는다. `--session-hours`(최대 수명)와는 별개로 둘 다 적용된다. |

로그인 잠금: 같은 사용자 이름을 **같은 클라이언트 주소**에서 15분에 5번 틀리면 그 주소만 잠기고(다른 주소의 같은 계정은 안 잠긴다), **모든 주소를 합쳐** 한 이름에 15분에 50번 틀리면 그 이름이 잠긴다(분산 추측 상한). 시도는 확인 **전에** 센다(동시에 보낸 요청이 한도를 넘기지 못한다; 비밀번호 해시를 못 한 503이나 2단계 코드만 요구한 응답은 되돌려 준다). 2단계 화면(setup·disable·recovery-codes)은 계정 id와 주소별로 같은 한도를 따로 센다. 한도에 닿으면 올바른 비밀번호도 429다.

### 3. Apache 예 (별도 호스트 이름 `rms.example.org`)
UI가 `/api/v1`·`/_app`을 절대 경로로 부르므로 하위 경로(`/rms/`)가 아니라 **별도 호스트 이름**에 올린다. 모듈: `ssl proxy proxy_http headers rewrite`(+ 속도 제한에 `evasive` 또는 `qos`).
```apache
<VirtualHost *:80>
    ServerName rms.example.org
    RewriteEngine On
    RewriteRule ^/(.*)$ https://rms.example.org/$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName rms.example.org
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/rms.example.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/rms.example.org/privkey.pem
    Header always set Strict-Transport-Security "max-age=31536000"

    # 방문자가 보낸 전달 헤더를 먼저 모두 지운다. mod_proxy_http가 X-Forwarded-For/Host/Server를
    # 새로 붙이므로 서버는 "프록시가 쓴 값"만 보게 된다. Forwarded·X-Real-IP는 Apache가 만들지
    # 않으니 지우기만 한다.
    RequestHeader unset Forwarded early
    RequestHeader unset X-Forwarded-For early
    RequestHeader unset X-Forwarded-Host early
    RequestHeader unset X-Forwarded-Proto early
    RequestHeader unset X-Forwarded-Server early
    RequestHeader unset X-Real-IP early
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPreserveHost On
    ProxyRequests Off

    # 내부 지표는 밖에 내지 않는다(코드상 viewer 이상이 읽을 수 있다).
    <LocationMatch "^/metrics">
        Require all denied
    </LocationMatch>

    # 실시간 스트림(SSE)은 버퍼링 없이, 오래 열어 둔다.
    SetEnvIf Request_URI "^/api/v1/stream" no-gzip
    ProxyPass        /api/v1/stream http://127.0.0.1:8080/api/v1/stream flushpackets=on timeout=3600
    ProxyPassReverse /api/v1/stream http://127.0.0.1:8080/api/v1/stream
    ProxyPass        / http://127.0.0.1:8080/ timeout=120
    ProxyPassReverse / http://127.0.0.1:8080/

    # (선택) 접속할 수 있는 주소를 사무실·VPN 대역으로 제한한다.
    # <Location "/">
    #     Require ip 203.0.113.0/24 198.51.100.7
    # </Location>
</VirtualHost>
```
- **로그인 속도 제한**은 프록시에서도 건다(서버 쪽 한도는 마지막 방어선): `mod_evasive`(`DOSPageCount`·`DOSSiteCount`·`DOSBlockingPeriod`)나 `mod_qos`(`QS_LocRequestLimitMatch "^/api/v1/auth/" 5`)로 `/api/v1/auth/*`를 주소당 낮게 제한하거나, fail2ban으로 실패한 로그인을 밴한다:
  ```
  # /etc/fail2ban/filter.d/dhonomos-login.conf
  [Definition]
  failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST /api/v1/auth/login HTTP/[\d.]+" 40[13]
  # /etc/fail2ban/jail.d/dhonomos-login.local
  [dhonomos-login]
  enabled  = true
  port     = http,https
  filter   = dhonomos-login
  logpath  = /var/log/apache2/rms.example.org-access.log
  maxretry = 12
  findtime = 10m
  bantime  = 1h
  ```
  (2단계가 켜진 계정은 코드를 묻는 첫 응답도 401이라 로그인 한 번이 401 한 번을 만든다. `maxretry`를 5보다 넉넉하게 잡는다.)
- `/api/v1/openapi.json`·`/api/v1/auth/config`는 의도적으로 공개다(API 설명, SSO 사용 여부). 막고 싶으면 `LocationMatch`로 같이 막는다(UI는 `auth/config`를 로그인 화면에서 쓰므로 그것은 막지 않는다).

### 4. 열기 전에, 연 뒤에
```
scripts/security-check.sh --public-url https://rms.example.org     # 이 호스트에서; sudo로 돌리면 ufw도 본다
DHONOMOS_CHECK_TOKEN=<admin API 키> scripts/security-check.sh --public-url https://rms.example.org   # + 2단계 없는 admin
```
읽기 전용이며 비밀값은 설정 여부·길이만 보여 준다. `TRUSTED_PROXIES`·`PUBLIC_URL`·`REQUIRE_TOTP_ROLES`·`SESSION_IDLE_MINUTES`를 포함한 서버 설정, 열린 소켓, 공개 주소의 TLS·HSTS·열린 모드·`/metrics`를 PASS/WARN/FAIL로 보여 준다(종료 코드 0·1·2). 디버그 빌드가 아닌 릴리스 빌드를 쓴다. 로그인 잠금·속도 제한은 스크립트로 확인하지 않으니 한 번 직접 시험한다(틀린 비밀번호를 여러 번 보내 429가 오는지, 다른 네트워크에서는 안 막히는지).

로그에서 볼 것: `failed login`(사용자 이름·클라이언트 주소), `cross-origin change request refused`, 프록시 설정 힌트(`--trusted-proxies is not set`, `X-Forwarded-Proto: https` + `--secure-cookies` 꺼짐). 감사 기록 `auth.login`의 `detail.client`에 로그인한 주소가 남는다.

## 3a. 단일 로그인(OIDC)
사내 IdP(Keycloak, Entra ID, Okta 등)로 로그인한다(ADR-070).
1. IdP에 클라이언트 등록: Authorization Code, 리디렉트 URI `https://<dhonomos>/api/v1/auth/oidc/callback`, ID 토큰에 그룹 클레임(Keycloak은 "Group Membership" 매퍼, 전체 경로 끔).
2. 설정:
   ```
   DHONOMOS_OIDC_ISSUER=https://sso.example/realms/isp
   DHONOMOS_OIDC_CLIENT_ID=dhonomos
   DHONOMOS_OIDC_CLIENT_SECRET=...
   DHONOMOS_OIDC_REDIRECT_URL=https://dhonomos.example/api/v1/auth/oidc/callback
   DHONOMOS_OIDC_ADMIN_GROUPS=dhonomos-admins
   DHONOMOS_OIDC_OPERATOR_GROUPS=noc
   DHONOMOS_OIDC_VIEWER_GROUPS=helpdesk
   ```
3. 로그인 화면에 "Sign in with single sign-on"이 나온다. 사용자는 `sso:<이름>`으로 보이고 역할은 로그인할 때마다 그룹에서 다시 정해진다. 그룹이 맞지 않으면 로그인이 거부된다(`sso_error`).
- 로컬 `admin` 계정은 IdP 장애 대비용으로 남겨 둔다.

## 3b. 장비 범위(팀별 권한)
viewer·operator 계정과 API 키를 일부 장비로 제한한다(ADR-074). 예: 부산 NOC는 `region=busan` 장비만.
- 설정: UI Settings → 사용자 추가·키 생성 시 **Device scope** 칸, 기존 사용자는 목록의 **Scope**. 형식은 쉼표로 구분한 조건: `tag:east`, `region=busan`(속성), `protocol:cwmp`, `oui:00259E`, `product_class:HG8245`. 모든 조건을 만족하는 장비만 범위 안이다. 빈 칸은 모든 장비.
- API: `POST /api/v1/users {"username": ..., "role": "operator", "scope": {"attributes": {"region": "busan"}}}`, `PATCH /api/v1/users/{id} {"scope": null}`(범위 해제), `POST /api/v1/api-keys {..., "scope": {"tags": ["east"]}}`.
- 범위 사용자에게는: 범위 밖 장비가 **없는 것처럼** 보인다(404). 목록·개요·CSV·알람·SSE도 범위 안만. 잡·사일런스는 대상이 범위로 좁혀져 저장된다. 장비 수정이 범위를 벗어나게 하면 거부된다. 장비 사전 등록·속성 CSV 가져오기·파일 업로드/삭제·`/metrics`는 할 수 없다(403). 감사 로그는 자기 행위만.
- admin에는 범위를 줄 수 없다(계정을 관리하므로). OIDC 사용자(`sso:`)는 처음 로그인한 뒤 관리자가 범위를 준다. 범위는 이후 로그인에도 유지되며, IdP 그룹이 admin이어도 범위가 있으면 operator로 동작한다.
- 범위에 쓰는 태그·속성은 범위 없는 운영자나 속성 CSV 가져오기로 관리한다. 장비가 범위를 정하는 태그·속성을 잃으면 그 팀에게서 사라진다.

## 3c. 2단계 인증(TOTP)
로컬 계정(비밀번호 로그인)에 인증 앱(Google Authenticator, Microsoft Authenticator, Aegis, 1Password 등)의 6자리 코드를 더한다(ADR-100). **기본은 admin 필수, operator·viewer는 선택**이다. 필수 역할은 `--require-totp-roles`(`DHONOMOS_REQUIRE_TOTP_ROLES`, 쉼표로 구분한 `admin,operator,viewer`, `none` = 없음, 기본 `admin`)로 정한다. 옛 `--require-admin-totp`(`DHONOMOS_REQUIRE_ADMIN_TOTP`)는 호환용으로 남아 있고, **명시했을 때만** admin을 목록에 더하거나(`true`) 뺀다(`false`). 명시하지 않으면 목록만 본다. 인터넷에 여는 설치는 `admin,operator`를 권한다([2b](#2b-관리-ui를-인터넷에-열기1단계)).
- **필수 조건**: `--secrets-key`(비밀은 암호화해 저장한다). 필수 역할이 하나라도 있는데 키가 없으면 기동을 거부한다(오류가 `--require-totp-roles none`·`--require-admin-totp false`를 안내한다). 발급자 이름은 `DHONOMOS_TOTP_ISSUER`(기본 `Dhonomos`)로 앱에 `<발급자>:<사용자명>`으로 보인다.
- **켜기**: 로그인 후 오른쪽 위 **Account** → Two-factor authentication → **Set up** → 앱으로 QR을 읽거나(키를 직접 입력해도 된다) 앱의 6자리 코드를 입력 → **Turn on**. 그러면 **복구 코드 10개**가 한 번만 나온다(Copy / Download .txt). 켜는 순간 그 계정의 다른 세션은 모두 끊긴다.
- **필수 역할의 첫 로그인**(예: admin): 비밀번호로 로그인하면 2단계가 없는 그 역할 계정의 세션은 **등록 전용**이다. Account 화면으로 바로 가고, 등록을 마칠 때까지 다른 모든 API가 403 `two-factor enrollment required`를 돌려준다(`GET /auth/me`, 로그아웃, `POST /auth/totp/setup|enable`만 열려 있다). 일반 사용자를 필수 역할로 올려도 다음 요청부터 같다. 설정을 마치면 같은 세션이 곧바로 완전해진다.
- **로그인**: 사용자명·비밀번호를 보내면 화면이 "Authentication code"를 묻는다. 휴대폰이 없으면 **Use a recovery code**로 복구 코드를 넣는다. 틀린 코드는 틀린 비밀번호와 똑같이 센다(같은 이름·같은 주소 5회/15분, 모든 주소 합쳐 이름당 50회/15분 잠금; [2b](#2b-관리-ui를-인터넷에-열기1단계)). 같은 코드는 한 번만 받는다 — 방금 쓴 코드는 앱이 다음 코드를 보일 때까지(최대 30초) 다시 쓸 수 없다. 서버 시계가 맞아야 한다(NTP; 앞뒤 30초까지 받는다).
- **복구 코드**: 한 번씩만 쓰이고(사용하면 감사 기록 `auth.recovery_code_used`와 남은 개수), Account → **New recovery codes**(앱 코드 필요)로 새로 만들면 옛 코드는 모두 무효가 된다. 안전한 곳(비밀번호 관리자 등)에 둔다.
- **휴대폰을 잃었을 때**(순서대로):
  1. 복구 코드가 있으면 그것으로 로그인 → Account → **Set up a new device**(코드 칸에 복구 코드) → 새 앱에서 확인. 새 기기가 확인되기 전에는 옛 기기가 계속 동작하고, 확인되면 옛 기기·옛 복구 코드가 무효가 되며 새 복구 코드가 나온다. admin도 이렇게 바꾼다(admin은 2단계를 끌 수 없다).
  2. 복구 코드도 없으면 **다른 admin**이 Settings → 사용자 → **Reset two-factor**(API `DELETE /api/v1/users/{id}/totp`)를 누른다. 그 사용자의 세션이 모두 끊기고, 비밀번호만으로 로그인한 뒤 다시 등록한다(필수 역할이면 등록 전용 세션). 감사 기록 `totp.reset`. 자기 계정은 이 방법으로 초기화할 수 없다.
  3. 유일한 admin이 둘 다 잃었으면 DB에서 직접 지운다(서버를 멈출 필요 없음):
     ```
     psql "$DHONOMOS_DATABASE_URL" -c "DELETE FROM user_totp WHERE user_id = (SELECT id FROM users WHERE username = 'admin')" \
       -c "DELETE FROM user_recovery_codes WHERE user_id = (SELECT id FROM users WHERE username = 'admin')" \
       -c "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = 'admin')"
     ```
     그 뒤 비밀번호로 로그인하면 다시 등록 화면이 나온다.
- **끄기**: 일반 사용자는 Account → **Turn off two-factor authentication**(비밀번호 + 코드 또는 복구 코드). 필수 역할의 계정은 끌 수 없다.
- **적용되지 않는 자격증명**(의도된 것): `--api-token`, **API 키**(기계 자격증명; 키를 만드는 사람은 2단계를 거친 admin이어야 하고, 키는 폐기하거나 만든 계정을 비활성화해 멈춘다), **SSO(OIDC) 로그인**(IdP가 2단계를 맡는다; SSO 전용 계정은 TOTP를 켤 수 없다), 계정이 없는 loopback 열린 모드. 비밀번호가 있는 계정이 SSO로도 로그인할 수 있어도, 그 계정의 **비밀번호 로그인**은 이 규칙을 따른다.
- **키 회전·분실**: TOTP 비밀은 `--secrets-key`로 봉인되어 키 회전(2번 절)에 함께 다시 봉인된다. 키를 잃으면 2단계가 켜진 계정의 앱 코드는 열 수 없어 로그인이 503이 되지만, 복구 코드(해시)는 그대로 동작하므로 복구 코드로 로그인해 새 기기를 등록한다.
- **감사**: `totp.setup`, `totp.enable`, `totp.disable`, `totp.recovery_codes`, `totp.reset`, `auth.recovery_code_used`, 그리고 `auth.login`의 `second_factor`(`totp`·`recovery_code`).

## 4a. 설정 다시 읽기 (재기동 없이)
DB에 둔 프리셋(기본, [프리셋 가이드](presets.md))은 저장하면 모든 프로세스가 5초 안에 반영하므로 따로 할 일이 없다. 프리셋 파일(`--presets`, 스크립트 포함)과 알람 규칙 파일은 **SIGHUP**으로 다시 읽는다.
```bash
docker compose kill -s HUP dhonomos      # 또는 kill -HUP <pid>
```
- 새 파일이 검증·컴파일에 실패하면 오류 로그(`presets not reloaded; keeping the running ones`)를 남기고 **기존 설정을 그대로 쓴다**.
- 알람 규칙에서 빠진 규칙의 활성 알람은 다음 평가(1분 이내)에 해제된다.
- 다른 플래그(포트·DB·비밀값)는 재기동해야 바뀐다.

## 4b. 가입자 연결(장비 속성)
장비에 가입자 번호·PPPoE 계정·회선 ID 같은 외부 ID를 key/value 속성으로 붙인다(ADR-067).
- 한 대씩: UI 장비 상세 → Attributes → Edit, 또는 `PATCH /api/v1/devices/{id} {"attributes": {"subscriber": "S-1001", "old": null}}`.
- 일괄(OSS/BSS 내보내기): UI 장비 목록 → Import attributes, 또는
  ```bash
  curl -X POST -H 'content-type: text/csv' --data-binary @subscribers.csv \
       -H "Authorization: Bearer $TOKEN" 'http://dhonomos:8080/api/v1/devices/attributes/import?dry_run=true'
  ```
  첫 열은 `serial_number`·`endpoint_id`·`id` 중 하나, 나머지 열 이름이 속성 키. 빈 칸은 기존 값을 유지한다. `dry_run=true`로 먼저 확인하고 빼면 반영된다.
- 찾기: 장비 목록의 속성 필터(`subscriber=S-1001`) 또는 검색창(속성 값 부분 일치), `GET /api/v1/devices?attr=subscriber=S-1001`.
- 쓰기: 프리셋 `when: { attributes: { plan: gold } }`, 스크립트 `device.attribute("plan")`, 잡·알람 규칙·사일런스 대상 `devices: { attributes: { plan: gold } }`.

## 4c. 파일 서버 대역폭과 다운로드 기록
펌웨어 캠페인이 업링크를 채우지 않게 파일 서버(7548)를 제한한다(ADR-076).
- `--files-total-mbps`: 모든 다운로드 합계(Mbit/s). `--files-download-mbps`: 다운로드 하나당. `--files-max-downloads`: 동시 다운로드 수 — 넘으면 503 + `Retry-After: 60`을 주고, CPE는 Download 실패(9010 등)를 보고하며 작업이 재시도된다.
- 캠페인의 `max_in_flight`(동시 진행 장비 수)와 함께 정한다. 예: 업링크 1 Gbit/s에서 `--files-total-mbps 500`, 펌웨어 50 MB를 장비당 20 Mbit/s로 → 약 20초, 동시 25대가 합계를 채운다.
- 기록: 다운로드가 끝날 때(또는 끊길 때) 장비 이벤트 `file_download`에 보낸 바이트·초·완료 여부(`complete`)·Range가 남는다(UI 장비 → Events). 지표: `dhonomos_file_downloads_total{outcome=served|failed|denied|busy|aborted}`, `dhonomos_file_download_bytes_total`, `dhonomos_file_downloads_active`.

## 4c-1. 파일 서버 HTTPS와 인증서 갱신
파일 서버(7548)는 기본이 평문 HTTP다. 인증서를 주면 같은 주소(`--files-listen`)에서 HTTPS(TLS 1.2 이상)로 응답한다.
- `--files-tls-cert <PEM 체인>`과 `--files-tls-key <PEM 키>`(환경 변수 `DHONOMOS_FILES_TLS_CERT/KEY`, 별칭 `--file-server-tls-cert/key`)를 **둘 다** 준다. 하나만 주면 기동 오류, 둘 다 없으면 평문이다.
- CPE에 건네는 서명 링크의 주소는 `--files-public-url`이다. 생략하면 TLS를 켠 경우 `https://127.0.0.1:7548`이 기본이므로 운영에서는 `https://acs.example.net:7548`처럼 직접 준다(`--role api` 프로세스도 같은 값을 줘야 링크가 맞는다). TLS를 켰는데 `http://`이거나, 평문인데 `https://`이면 기동 때 경고가 남는다(후자는 앞단 TLS 프록시면 정상).
- CPE가 서버 인증서를 믿어야 한다: 사설 CA면 CPE에 그 CA를 넣는다. IP로 접속하는 CPE는 인증서에 그 IP(SAN)가 있어야 한다.

인증서는 재기동 없이 바뀐다. 공인 인증서는 90일마다 갱신되므로, 파일 서버·ACS(`--acs-tls-cert/key`)·XMPP 서버(`--xmpp-tls-cert/key`)·wss와 STOMP·MQTT 브로커 over TLS(`--usp-ws-tls-cert/key`)는 인증서·키 **파일**을 1분마다 확인한다(수정 시각·크기).
- 파일이 바뀌면 두 파일을 다시 읽어 파싱하고 키가 인증서와 맞는지 확인한 뒤 교체한다. **새 연결부터** 새 인증서를 쓰고, 열린 연결은 그대로다. 로그 `TLS certificate reloaded`(경로와 만료일).
- 실패하면(쓰는 중인 파일, 키 불일치, 형식 오류) 기존 인증서를 그대로 쓰고 로그 `TLS certificate reload failed; keeping the current certificate`를 파일 상태마다 한 번 남긴다. 매 확인마다 다시 시도하므로 파일을 고치면 곧 반영된다.
- 갱신 도구가 파일을 쓰는 순서와 무관하지만, 가능하면 임시 파일에 쓴 뒤 이름을 바꾸는 방식(certbot의 심볼릭 링크 교체 포함)이 가장 깔끔하다.
- 지표: `dhonomos_tls_reload_total{listener="acs|files|xmpp|usp_wss|usp_stomp|usp_mqtt_broker", result="ok|error"}`. `error`가 계속 늘면 아직 못 읽는 상태다.
- `--usp-ca-dir`의 CA가 발급한 wss·STOMP·MQTT 브로커 인증서(`--usp-ws-tls-cert` 없음, 유효기간 90일)는 파일이 없으므로 **만료 7일 전에 자동으로 다시 발급**한다. 기동 때 한 번, 이후 1시간마다 만료일을 확인하고(시계가 바뀌거나 호스트가 멈췄다 깨어나도 1시간 안에 알아챈다), 만료까지 7일 이하면 같은 이름(SAN)으로 새 키를 만들어 새 인증서를 발급해 교체한다. 새 연결부터 새 인증서를 쓰고 열린 연결은 그대로다. 로그 `TLS certificate renewed`(`listener`와 새 만료일).
- 재발급이 실패하면(서명·난수 생성 오류 등. CA 키는 기동 때 메모리에 올려 두므로 파일에는 다시 접근하지 않는다) 기존 인증서를 그대로 쓰고 로그 `TLS certificate renewal failed; keeping the current certificate`를 남기며 다음 확인(1시간 뒤)에 다시 시도한다. 같은 지표 `dhonomos_tls_reload_total`에 `result="error"`가 쌓인다. 발급한 인증서는 어디에도 저장하지 않는다(기동할 때마다 새로 발급, wss·STOMP·MQTT 브로커는 각각 따로 발급·갱신).

## 4c-2. MQTT 브로커 TLS
Controller와 broker 사이를 TLS로 보호한다(ADR-081).
- `--usp-mqtt-tls`와 `--usp-mqtt-port 8883`을 준다.
- 브로커 인증서가 사설 CA라면 `--usp-mqtt-ca <pem>`을 준다.
- 브로커가 클라이언트 인증서를 요구하면(Mosquitto `require_certificate true`) `--usp-mqtt-client-cert/--usp-mqtt-client-key`를 준다.
- 인증서의 이름이 접속 주소와 다르면 `--usp-mqtt-tls-name`으로 맞춘다.
- dynamic-security 관리 연결(`--usp-dynsec`)에도 같은 설정이 쓰인다.
- 내부 구조: 프로세스 안에서 Unix 소켓 다리(`<files-dir>/.mqtt-tls/`, 권한 0700)를 거쳐 TLS를 건다. 이 디렉터리는 지우지 않는다(실행 중 다시 만든다).

## 4c-3. USP 연결 상한과 멈춘 Agent
Dhonomos가 직접 받는 USP 접속(내장 STOMP·MQTT 브로커, WebSocket)에서 Agent 하나가 자원을 다 쓰거나 전체를 멈추지 못하게 한다(보안 점검 H-4·H-5·M-6).
- **연결 상한**(STOMP·MQTT 브로커): `--usp-stomp-max-connections`·`--usp-mqtt-broker-max-connections`(기본 20000)와 `--usp-stomp-max-connections-per-ip`·`--usp-mqtt-broker-max-connections-per-ip`(기본 256, IPv6는 /64 단위). 환경 변수는 `DHONOMOS_USP_STOMP_MAX_CONNECTIONS`, `DHONOMOS_USP_STOMP_MAX_CONNECTIONS_PER_IP`, `DHONOMOS_USP_MQTT_BROKER_MAX_CONNECTIONS`, `DHONOMOS_USP_MQTT_BROKER_MAX_CONNECTIONS_PER_IP`. 0은 끔. 넘는 연결은 accept 직후 닫는다(TLS 핸드셰이크·읽기 버퍼 전). TLS 종단 프록시나 CGNAT 뒤에서 Agent가 한 주소로 보이면 주소별 상한을 올리거나 0으로 한다.
- **STOMP 프레임 크기**: 로그인(`STOMP`/`CONNECT`) 전에는 프레임 전체가 8 KiB, 로그인 후에도 명령·헤더 블록은 16 KiB, 헤더는 64개까지다. 본문(Record)은 로그인 후 8 MiB까지. 넘으면 연결을 닫는다(`dhonomos_usp_stomp_rejected_total`).
- **MQTT 브로커 패킷 크기**: CONNECT 이후 PUBLISH 외 패킷은 16 KiB(고정 헤더만 보고 DISCONNECT 0x95로 거절, 본문을 받지 않는다). 한 SUBSCRIBE·UNSUBSCRIBE의 필터는 16개, PUBLISH·SUBSCRIBE·UNSUBSCRIBE의 속성 영역은 4 KiB까지이며 넘으면 DISCONNECT 0x97(디코딩하지 않는다).
- **MQTT Keep Alive**: 최대 1200초. 더 길게(최대 65535초) 요청하는 클라이언트에는 CONNACK의 Server Keep Alive로 1200을 알리고, 그 값의 1.5배 동안 완전한 패킷이 없으면 DISCONNECT 0x8D로 끊는다. 패킷은 첫 바이트부터 60초(큰 PUBLISH는 64 KiB당 1초 추가) 안에 전부 와야 한다. 바이트를 조금씩 흘려 보내도 연결을 붙잡을 수 없다.
- **읽지 않는 Agent**: Agent별 송신 큐(64개)가 차면 그 Agent로의 전송은 즉시 실패한다("agent send queue full", 작업은 다음 접속 때 다시 나간다). 다른 Agent의 처리는 늦어지지 않는다. 연결은 STOMP·MQTT 브로커·WebSocket 모두 쓰기가 30초(WebSocket은 Record 128 KiB당 1초 추가) 안에 끝나지 않으면 닫는다. MQTT 브로커는 Agent의 Receive Maximum 창이 PUBACK 없이 60초 동안 가득 차 있으면 닫는다. Controller의 NotifyResp·Error 답신은 수신 루프 밖에서 Agent별 순서대로 보내고, Agent당 32개·전체 8192개를 넘으면 버린다.

## 4d. USP Agent 인증서
`--usp-ca-dir`의 CA가 Agent에 발급한 인증서(wss 클라이언트 인증, ADR-035/080).
- 발급:
  - UI 장비(USP) → **Certificates** → Issue certificate. CSR을 붙여 넣으면 키가 Agent 밖으로 나오지 않는다. CSR 없이 발급하면 키를 만들어 한 번만 보여 주고(서버에 저장하지 않음), 바로 설치할 수 있는 `client.pem`(인증서 + 키) 내려받기를 함께 준다. 기본 유효기간은 1095일(3년)이다.
  - API: `POST /api/v1/devices/{id}/certificate`. 키를 만들었다면 응답의 `client_pem`이 `obuspa -a`가 읽는 형식(인증서 다음에 개인 키)이다.
  - 여러 장비를 한 번에, 장비 운영자에게 넘길 때는 아래 [4d-1](#4d-1-agent-인증서-발급설치)의 번들을 쓴다. 접속한 적 없는 장비(시리얼 목록만 있는 장비)도 된다.
  - 장비 설정 주의: obuspa는 WebSocket 경로 뒤에 `?eid=<EID>`를 스스로 붙이므로 경로는 `/usp`만 넣는다(`/usp?eid=…`면 중복돼 400). 장비 신뢰 저장소에는 `ca.pem`만 넣는다 — 장비 자기 인증서(`cert.pem`)를 CA로 넣으면 obuspa 11.0.7이 기동 중 죽는다(펌웨어 업로드 화면이 거부하도록 고침). LTE57X처럼 MAC 설정 전 시리얼이 임시값(eMMC CID)인 장비는 시리얼이 확정된 뒤 발급한다(EID가 바뀌면 재발급).
  - 인증서가 발급된(폐기하지 않은 것이 하나라도 있는) EndpointID는 **모든 MTP에서 인증서 없는 접속을 거부한다**(wss·평문 `ws://`는 403, STOMP는 ERROR 프레임, 내장 MQTT 브로커는 CONNACK 0x87). 공용 STOMP·MQTT 계정을 가진 쪽이 그 EndpointID를 주장해 인증서 장비 행세를 하지 못하게 하려는 것이다(ADR-098). 발급 뒤 10초 안에 반영되고, 이미 열려 있는 연결은 끊지 않는다. 인증서를 장비에 넣기 전에 끊긴 장비는 공용 계정으로 다시 붙지 못하므로, 급하면 그 인증서를 폐기해 풀어 준다. 만료된 인증서도 폐기하기 전까지 묶어 둔다. 로그의 `connection refused`·`dhonomos_usp_*_rejected_total`로 거절을 본다.
- 폐기:
  - 장비 분실·키 유출 시 같은 화면의 **Revoke**(admin), 또는 `POST /api/v1/devices/{id}/certificates/{cert}/revoke {"reason": "..."}`.
  - 10초마다 폐기 목록을 읽어, 그 인증서로 연결된 Agent를 wss·TLS STOMP·TLS 내장 MQTT 어디서든 끊고(MQTT는 DISCONNECT 0x87) 이후 접속을 거부한다(wss는 403).
  - 외부 MQTT 브로커로 붙는 Agent는 브로커가 TLS를 끝내 Dhonomos가 인증서를 보지 못하므로, 브로커 계정을 회수한다(`DELETE /devices/{id}/mqtt-credentials`).
  - **장비를 삭제하면**(`DELETE /api/v1/devices/{id}`, 퇴역한 장비만) 그 장비의 폐기하지 않은 인증서를 **먼저 모두 폐기**한다(사유 `device deleted`, 폐기자는 삭제한 계정). 인증서는 장비 기록이 없어져도 최대 3년간 암호학적으로 유효하므로, 기록을 지우면 폐기할 수도 없고 폐기 목록에서도 빠져 MTP가 다시 받아들이게 된다. 그래서 인증서 기록은 지우지 않고 장비 없이(`device_id`가 비어) 남기며, 폐기 목록에 그대로 있다(만료 전까지). 감사 기록 `device.delete`의 `certificates_revoked`가 이때 폐기한 개수다. 삭제된 장비의 인증서는 장비 화면에 더는 나오지 않으므로, 다시 다뤄야 하면 아래 지문으로 한다.
  - **여러 장비를 한 번에 삭제**(`POST /api/v1/devices/delete`, admin 전용이며 장치 범위가 있는 계정은 쓸 수 없다): UI Devices 목록에서 체크박스로 고르면(페이지를 넘겨도 선택이 유지된다) 빨간 **Delete N devices** 버튼이 나타난다. 확인 창이 지울 장비(앞 20개와 "and N more")와 결과(장비의 모든 데이터 삭제, Agent 인증서 폐기, 퇴역하지 않은 장비는 먼저 퇴역, 아직 쓰는 장비는 다음 접속 때 새 장비로 다시 등록됨)를 알려 주고, 장비 수 N을 직접 입력해야 **Delete**가 켜진다. 한 번에 최대 1000대다.
    ```
    POST /api/v1/devices/delete
    {"device_ids": ["<장비 UUID>", "..."], "retire": true}
    ```
    **전부 검사한 뒤에 지운다**: 목록에 없는 장비·같은 장비를 두 번 적은 경우·(`retire`가 거짓일 때) 퇴역하지 않은 장비가 하나라도 있으면 아무것도 지우지 않고 422로 해당 장비(최대 20개)를 알려 준다. `retire`가 참이면 퇴역하지 않은 장비를 먼저 퇴역시킨 뒤 지운다(UI는 항상 참으로 보낸다). 각 장비는 위 단일 삭제와 같은 경로로 하나씩 지워지므로 인증서 폐기·기록 유지·업로드 파일 삭제가 똑같고, 응답은 `{"deleted": n, "certificates_revoked": n, "files": n}`이다. 중간에 실패하면(예: 외부 MQTT 브로커 계정을 못 지우면 502) 그 앞의 장비는 이미 지워진 채로 두고, 오류 메시지가 몇 대가 지워졌는지 알려 준다. 감사 기록은 장비마다 `device.delete`(`bulk: true`, `retired_first`가 퇴역을 먼저 했는지)와 요청마다 하나의 요약 `device.delete_bulk`(요청·삭제·퇴역 수, 폐기한 인증서·삭제한 파일 수, 앞 10개 이름, `complete`)다. 퇴역은 장비 기록과 함께 지워지므로 `device.status` 기록을 따로 남기지 않는다.
  - **지문으로 폐기**: 장비 기록이 없는 인증서(삭제 전 폐기하지 않고 지운 장비, 기록을 잃은 인증서)는 SHA-256 지문으로 폐기한다. admin 전용이며 장치 범위가 있는 계정은 쓸 수 없다. 지문은 인증서 발급 때 감사 기록(`certificate.bundle`, `device.certificate.issue`)에 남아 있다.
    ```
    POST /api/v1/certificates/revoke
    {"sha256": "<64자리 16진수>", "endpoint_id": "os::agent-1", "reason": "device deleted without revoking"}
    ```
    `endpoint_id`와 `reason`은 선택이다(기록용). 지문은 대소문자와 `openssl x509 -fingerprint -sha256`의 `:` 구분을 가리지 않는다. Dhonomos가 그 지문의 기록을 갖고 있으면 그 인증서를 폐기하고, 없으면 폐기된 기록(장비·일련번호·만료일 없음)을 새로 만든다. 만료일을 모르는 기록은 폐기 목록에 계속 남는다. 응답의 `known`이 기록이 이미 있었는지를 알려 준다. 이미 폐기된 지문을 다시 폐기해도 처음 폐기한 시각·계정·사유가 유지된다. 10초 안에 모든 MTP에 반영된다. 감사 기록은 `certificate.revoke`.
- 제조사 공장 인증서: Agent가 제조사 CA가 발급한 인증서(SAN에 EndpointID)를 갖고 있으면 `--usp-ws-client-ca <제조사 CA PEM>`으로 함께 신뢰한다. 우리 CA가 없어도 쓸 수 있다. 이 인증서는 Dhonomos가 발급 기록을 갖고 있지 않으므로 폐기는 브로커 계정 회수나 장비 격리로 한다.
- 만료:
  - `GET /api/v1/certificates/expiring?days=30`은 30일 안에 만료되는 인증서 목록이다. 이미 새 인증서를 받은 장비는 빠진다.
  - 갱신은 새로 발급해 Agent에 설치하는 방식이다. TR-181에는 Agent 자기 인증서·키를 원격으로 넣는 표준 명령이 없다(`AddMyCertificate()`는 Controller 인증서용) — 운영자가 번들로 받아 장비마다 설치한다(4d-1). 만료 알람 규칙은 아직 없으므로 위 목록을 주기적으로(예: 매주 `days=90`) 확인한다.

## 4d-1. Agent 인증서 발급·설치
wss 인증서가 필수(ADR-094)이고 인증서가 발급된 EndpointID는 모든 MTP에서 인증서를 요구하므로(ADR-098), 장비마다 클라이언트 인증서를 넣어야 한다. TR-181에는 Agent의 인증서·키를 원격으로 넣는 표준 명령이 없어서, **Dhonomos가 키와 인증서를 만들어 서명하고 장비 운영자(설치 담당)가 장비마다 설치한다**(ADR-099). 실물 장비와 인증서를 사람이 짝짓는 것이 신원 확인이다. 잘못 짝지어도 접속 EID와 인증서 SAN의 EID를 서버가 대조하므로 사칭은 안 되고 접속만 실패한다.

**0. 장비 사전 등록(operator 이상)**
- 장비를 사면 발주서·출하 목록에 시리얼이 있다. 장비가 접속하기 전에 그 목록으로 장비를 등록해 두고(CO-12), 설치 전에 인증서를 발급한다.
- UI: Devices → **Add devices** → 한 줄에 장비 하나를 붙여 넣거나 CSV 파일을 고른다 → 태그(선택) → **Preview**(줄마다 *will add* / *already exists*(장비로 가는 링크) / *invalid*(이유)를 보여 주고 아직 아무것도 쓰지 않는다) → **Add N devices**. 한 번에 최대 10,000대이고, 일부 줄이 잘못돼도 나머지는 등록된다(줄별 결과). 이미 있는 장비는 그대로 둔다. 장치 범위(scope)가 있는 계정은 쓸 수 없다.
- 줄 형식(대화 상자에도 적혀 있다):
  - `os::B01408-B01408123456` — USP EndpointID. 규칙은 단건 사전 등록과 같다(`<스킴>::<인스턴스>`, `/`·`+`·`#`·제어 문자 없음).
  - `B01408,B01408123456` · `B01408 B01408123456` · `B01408-B01408123456` — OUI와 시리얼. **EndpointID는 `os::<OUI 대문자>-<시리얼>`**(TR-369의 `os` 권한 스킴)로 만든다. 위 예는 `os::B01408-B01408123456`이다. OUI는 16진수 6자리, 시리얼은 영문·숫자와 `. _ - : @ ~`만 쓸 수 있다(최대 200자). 이 형식을 쓰는 펌웨어는 CWMP의 OUI·시리얼과 같은 값으로 EID를 만들므로 이 규칙이 맞는다.
  - `00AA00,HG8245,48575443A1B2C3D4` — 세 칸(OUI, product class, 시리얼)이면 **CWMP 장비**로 등록한다(product class는 비워도 된다: `00AA00,,SN1`). CWMP는 OUI를 그대로 두고 규칙을 따로 검사하지 않는다(Inform의 DeviceId와 일치해야 하므로).
  - CSV는 같은 형식이다. 첫 줄에 열 이름(`endpoint_id`, `oui`, `serial` 또는 `serial_number`, `product_class`)을 두면 열 순서는 자유이고 product class가 있는 줄은 CWMP 장비다. 열 이름이 없을 때 EndpointID로 시작하는 줄의 뒷 열은 무시한다. 빈 줄과 `#`로 시작하는 줄은 건너뛴다.
- API: `POST /api/v1/devices/bulk` `{"devices": [{"endpoint_id": "os::…"}, {"oui": "B01408", "serial_number": "…"}, {"oui": "00AA00", "product_class": "HG8245", "serial_number": "…"}], "tags": ["batch-1"], "dry_run": false}`. 항목 하나는 `endpoint_id`(USP), `oui`+`serial_number`(USP, EID는 위 규칙으로 만든다), 또는 `oui`+`serial_number`+`product_class`(비어 있어도 키가 있으면 CWMP)다. 응답은 항목마다 `{index, status: added|exists|invalid, protocol, endpoint_id, device_id, error}`이고 `dry_run: true`면 아무것도 쓰지 않고 `added`는 "추가될 것"이다. 한 요청 안의 같은 장비는 첫 항목만 세고 나머지는 `invalid`(`duplicates an earlier entry`)다. 감사 기록은 `device.preregister_bulk`(추가된 개수·이미 있던 개수·잘못된 개수·태그·앞 10개).

**1. 발급(admin)**
- UI: Devices의 **Issue certificates**(admin에게는 항상 보인다) → 대상을 고르는 세 가지 방법 중 하나 → 유효기간(기본 1095일)과 zip 비밀번호(12자 이상, 두 번 입력) → **Download bundle**. 한 번에 최대 1000대(릴리스 빌드에서 수 초, 응답은 다 만든 뒤에 온다). 받은 뒤 화면에 발급한 개수와 새로 만든 장비 수가 나오고, zip과 비밀번호를 따로 전하라는 안내가 뜬다.
  1. **목록에서 고른 장비**: 목록의 체크박스(모든 행을 고를 수 있다. 같은 선택으로 장비를 삭제할 수도 있다). 접속한 적 없는 사전 등록 장비도, OUI와 시리얼이 있는 CWMP 장비도 발급 대상이다. 퇴역 장비와 OUI·시리얼이 없는 CWMP 장비는 건너뛰고, 대화 상자가 몇 대를 왜 건너뛰는지 알려 준다.
  2. **목록 붙여넣기·CSV**: 위 0과 같은 형식(EndpointID, 또는 OUI+시리얼. 세 칸 줄은 product class를 무시하고 OUI+시리얼로 본다). **아직 없는 장비는 같은 요청에서 USP 장비로 사전 등록**(입력한 태그)한 뒤 발급한다. 먼저 따로 등록할 필요가 없다.
  3. **필터 식**: 장비 목록 위의 필터와 같은 문법(예: `tag = batch-1 and protocol = usp`). 대화 상자가 일치하는 장비 수를 먼저 세어 보여 준다. 퇴역 장비는 빠지고, 1000대를 넘으면 자르지 않고 거부한다.
- **CWMP 장비**는 OUI와 시리얼로 만든 EID(`os::<OUI>-<시리얼>`)의 USP Agent를 대신한다. 그 EID의 USP 장비가 이미 있으면 그것에 발급하고, 없으면 사전 등록(CWMP 장비의 태그를 복사)한 뒤 발급한다. 인증서는 그 USP 장비에 묶이며 CWMP 장비 기록은 그대로다. OUI·시리얼이 없거나 EID에 쓸 수 없는 문자가 있으면 거부한다.
- API: `POST /api/v1/certificates/bundle`
  ```
  {"device_ids": [...], "endpoint_ids": [...],
   "targets": [{"endpoint_id": "os::…"}, {"oui": "B01408", "serial_number": "…"}],
   "filter": "tag = batch-1", "create_missing": false, "tags": ["batch-1"],
   "days": 1095, "password": "..."}
  ```
  이름 붙이는 방법(`device_ids`, `endpoint_ids`, `targets`, `filter`) 중 하나 이상이 필요하고 섞어 쓸 수 있다(합쳐서 1000대까지; 같은 장비가 `filter`와 이름 목록에 겹치면 한 대로 센다). `create_missing`(기본 false)이 true면 `endpoint_ids`·`targets`에서 아직 없는 Agent를 `tags`로 사전 등록한다(UI는 목록 입력에 true). false이면 없는 Agent는 거부한다. CWMP 장비의 Agent는 `create_missing`과 관계없이 만든다. 응답은 `application/zip`(`Content-Disposition: attachment`, `Cache-Control: no-store`)이고 헤더 `X-Certificates-Issued`(zip의 인증서 수)와 `X-Devices-Created`(새로 만든 장비 수)가 붙는다.
- **전부 검사한 뒤에 발급한다.** 모르는 장비·퇴역 장비·중복·EndpointID로 쓸 수 없는 OUI/시리얼·읽을 수 없는 필터·1000대 초과가 하나라도 있으면 **아무것도 발급하지도 만들지도 않고** 422로 문제 항목(최대 20개)을 알려 준다. 새 장비의 생성과 인증서 기록은 zip을 다 만든 뒤에 **한 트랜잭션으로 함께** 한다. 장치 범위(scope)가 있는 계정은 쓸 수 없다.
- 서버는 장비마다 새 키와 인증서(프로파일은 단건 발급과 같음)를 만들어 `usp_certificates`에 기록한다. 그래서 만료 임박 목록(`GET /api/v1/certificates/expiring`)과 폐기가 그대로 동작한다. 개인 키와 비밀번호는 저장하지도 로그에 남기지도 않는다. 감사 기록 `certificate.bundle`에는 누가·어느 EID·인증서 지문과 이때 만든 장비(`created_devices`)만 남는다.
- 번들을 다시 받아도 이전 인증서는 폐기되지 않는다. 잃어버렸거나 바꾼 인증서는 장비 화면 **Certificates**에서 Revoke 한다.
- 지표: `dhonomos_usp_certificates_issued_total{via="bundle"|"single"}`.

**2. 번들 내용과 비밀번호**
- `README.txt`(설치 안내), `ca.pem`(CA 인증서), `manifest.csv`(`endpoint_id,device_id,device_serial_number,certificate_serial,sha256_fingerprint,not_before,not_after,directory`), 장비마다 `<EID에서 :·/ 등을 _로 바꾼 디렉터리>/client.pem`(인증서 다음에 개인 키: `obuspa -a` 형식)과 `cert.pem`(인증서만). 이름이 겹치면 `-2`, `-3`을 붙이고, `manifest.csv`의 `directory`가 EID와 디렉터리를 이어 준다.
- zip은 **AES-256으로 암호화**된다. 7-Zip·WinZip·Keka 등으로 연다(리눅스 기본 `unzip`과 Windows 탐색기는 AES zip을 열지 못한다. 리눅스는 `7z x`). 파일 이름과 크기는 zip 규격상 암호화되지 않아 EndpointID 목록은 보인다.
- 비밀번호는 발급하는 사람이 정하고, zip과 **다른 경로**(전화·메신저 등)로 설치 담당자에게 전한다. zip의 AES는 PBKDF2 1000회로 키를 만들기 때문에 약한 비밀번호는 오프라인 대입에 약하다: 12자는 최소일 뿐이고, 무작위로 만든 16자 이상을 권장한다.
- 번들은 만든 PC와 전달 경로에 개인 키 전부가 있는 파일이다. 설치가 끝나면 **zip과 풀어 놓은 `client.pem`을 모두 지운다**(서버에는 키가 남지 않는다. 다시 필요하면 다시 발급한다).

**3. 설치(장비 운영자)**
1. `manifest.csv`에서 장비의 EndpointID로 디렉터리를 찾는다.
2. 그 `client.pem`을 장비에 복사한다(예: `/etc/obuspa/client.pem`, 권한 0600, Agent를 돌리는 사용자 소유).
3. obuspa에 `-a /etc/obuspa/client.pem`(펌웨어는 uci `obuspa.agent.client_cert`)을 주고, 장비가 `ca.pem`을 신뢰하게 한다(서버 인증서 검증용 trust store).
4. 모든 장비를 마치면 번들과 `client.pem` 사본을 지운다.

**4. 주의**
- **설치 직전에 발급한다.** 발급하는 순간 그 EndpointID는 **인증서를 요구**한다(ADR-098; 10초 안에 반영, 열려 있는 연결은 끊지 않는다). 장비가 아직 접속한 적이 없어도 마찬가지라서, 발급한 EID의 장비는 인증서를 설치하기 전에는 공용 계정으로도 붙지 못한다. 설치 담당자에게 번들을 넘길 준비가 된 뒤에 발급한다. 번들을 잃었다면 그 인증서를 폐기해 EndpointID를 풀어 준다.
- **시리얼이 확정된 뒤에 발급한다.** EID가 시리얼에서 만들어지므로 시리얼이 바뀌면 EID가 바뀌어 인증서가 맞지 않는다. 예: LTE57X는 MAC을 설정하기 전에는 시리얼이 eMMC CID 기반 임시값이고 설정 뒤 eth1 MAC 기반으로 바뀐다. 임시 시리얼로 발급하면 새 EID로 다시 발급해야 하고, 이전 EID는 인증서에 묶인 채 남는다(폐기하면 풀린다). 목록에 넣은 시리얼이 장비 라벨·출하 검수에서 정해진 최종 값인지 확인한다.
- 만료는 기본 3년이다. 만료 전에 새 번들로 다시 설치한다. 만료 알람은 아직 없으므로 `GET /api/v1/certificates/expiring?days=90`을 주기적으로 본다.
- 장비 분실·키 유출: 해당 인증서를 Revoke 한다(위 4d). 10초 안에 모든 MTP에서 그 인증서의 접속이 끊긴다.
- **CA 디렉터리(`--usp-ca-dir`)는 설치 사이에 복사하지 않는다.** 복사하면 두 설치가 같은 CA를 가져 한쪽이 발급한 인증서를 다른 쪽이 믿는다. 설치마다 새 CA를 만들고(`--usp-ca-name`을 주지 않으면 이름에 설치별 무작위 접미사가 붙는다), CA 키(`ca.key`, 0600)는 백업하되 다른 곳에 두지 않는다.
- **실험망 CA의 `ca.pem`이나 실험용 `client.pem`·키를 담은 펌웨어 패키지는 제품 이미지에 넣지 않는다.** 제품 장비가 실험망 CA를 믿으면 그 CA 키를 가진 누구나 서버로 위장할 수 있고, 이미지에 든 `client.pem`은 같은 이미지를 쓰는 모든 장비가 공유하므로 하나가 새면 전부의 신원이 샌다. 제품 장비에는 제품 설치의 CA를 신뢰하게 하고, 인증서는 장비마다 따로 넣는다.
- 장비가 키·CSR을 만들어 원격으로 등록하는 방식(키가 장비 밖으로 나가지 않음)은 등록 경로에서 "요청한 장비가 정말 그 EID인가"를 증명할 길이 있어야 해서 지금은 제공하지 않는다. 제조사가 공장에서 넣은 인증서는 `--usp-ws-client-ca`로 함께 신뢰한다(4d).

## 4e. 감사 로그 외부 전송
DB가 변조되어도 남는 사본을 SIEM·로그 수집기에 둔다(ADR-083).
- 설정: `--audit-webhook-url https://siem.example/dhonomos`와 `--audit-webhook-secret <비밀>`.
- 동작:
  - 프로세스 하나가 감사 기록을 오래된 순서로 최대 500건씩 POST한다. 본문은 `{"source": "dhonomos", "tenant_id", "records": [{id, occurred_at, actor, action, target_type, target_id, detail}]}`이고, `X-Dhonomos-Signature: sha256=<HMAC>`를 붙인다.
  - 2xx 응답을 받아야 다음으로 넘어간다. 실패하면 최대 5분까지 간격을 늘려 다시 보낸다.
  - 처음 켜면 기록 전체를 처음부터 보낸다.
  - 수신 측에서 같은 `id`가 다시 오면 중복이므로 버린다. 응답을 받기 전에 연결이 끊긴 경우에 생길 수 있다.
- 감시 지표: `dhonomos_audit_export_lag`(아직 보내지 않은 기록 수), `dhonomos_audit_export_failures_total`.

## 4f. USP Controller 구독과 데이터 모델 캐시
**자동 구독** (`--usp-auto-subscribe`, 환경 변수 `DHONOMOS_USP_AUTO_SUBSCRIBE`, 기본 `true`)
- 켜 두면 Agent가 접속할 때마다 Controller가 `Device.LocalAgent.Subscription.`에 구독 3개를 넣는다(이미 있는 ID는 건드리지 않는다): `dhonomos-boot`(`Device.Boot!`), `dhonomos-operation-complete`(`OperationComplete`, `Device.`), `dhonomos-bulkdata`(`Device.BulkData.Profile.*.Push!`).
- Agent에 Controller가 아무것도 쓰지 않게 하려면 `--usp-auto-subscribe=false`로 끈다(기동 시 info 로그 한 줄). 그러면 구독 표를 읽지도, 추가하지도 않는다. 대신 아래 기능은 **Agent에 같은 알림을 보내는 구독이 따로 만들어져 있을 때만** 동작한다. 폴링으로 대신하는 기능은 없다.
  - `Boot!`: 마지막 부팅 시각(`last_boot_at`) 갱신, 프리셋 `1 BOOT`, 펌웨어 이미지 다시 읽기(4f-1), 부팅 직후 대기 작업 실행. 없으면 Agent가 다시 접속할 때(`USP CONNECT`)만 반응한다.
  - `OperationComplete`: 비동기 명령(펌웨어 `Download()`, 설정·로그 `Backup()`/`Restore()`/`Upload()`, IPPing·TraceRoute 같은 진단)의 완료 처리. 없으면 작업이 `waiting`에 머물다가 24시간 뒤 "no completion report"로 실패한다.
  - `Device.BulkData.Profile.*.Push!`: USP로 보내는 BulkData 수집. HTTP BulkData(4c의 파일 서버)는 영향이 없다.
- 구독을 직접 만들 때는 `Recipient`를 Dhonomos Controller 항목(`Device.LocalAgent.Controller.{i}`)으로, `NotifType`/`ReferenceList`를 위 3개와 같게, `Persistent=true`로 둔다. 나중에 자동 구독을 다시 켜려면 같은 알림이 두 번 오지 않도록 직접 만든 구독을 먼저 지운다.

**지원 데이터 모델 캐시** (US-11, ADR-034)
- Agent에 `GetSupportedDM`을 한 번 보내 배운 모델을 펌웨어 지문(프로토콜·제조사·OUI·제품군·모델명·**SoftwareVersion**의 해시)별로 공유한다. 같은 펌웨어의 다른 Agent는 다시 묻지 않는다. 모델은 파라미터 쓰기 가능 여부(UI의 Edit 버튼)와 `GET /api/v1/devices/{id}/supported-model`에 쓰인다.
- `SoftwareVersion`이 비어 있거나 읽지 못한 Agent는 빌드를 구분할 수 없으므로 **공유 캐시를 쓰지 않는다**. 접속할 때마다 `GetSupportedDM`을 다시 보내고(로그 `supported data model cache skipped: the software version is unknown`, 접속당 한 번), 그 장비만의 모델로 저장한다. 장비를 지우면 함께 지워진다.
- `SoftwareVersion`이 빌드마다 같아서(예: 모두 `3.1.48`) 오래된 모델이 남는 경우에는 **수동으로 새로 고친다**.
  - UI: 장비(USP) → Parameters → **Refresh data model**. API: `POST /api/v1/devices/{id}/data-model/refresh`(operator, USP 장비만, CWMP는 422).
  - 응답은 202 `{"status": "refreshing"}`(Agent가 접속 중: 지금 `GetSupportedDM`을 보내고, 도착하면 모델을 그 자리에서 바꾼다. 같은 펌웨어의 다른 장비도 새 모델을 본다) 또는 `{"status": "queued"}`(Agent가 오프라인: 캐시된 모델을 지금 지우고 다음 접속 때 읽는다. 그때까지 같은 펌웨어의 다른 장비도 모델이 없고, 각자 다시 접속하면 채워진다).
  - 이미 저장된 파라미터의 쓰기 가능 표시는 그 파라미터를 다시 읽을 때(Parameters 탭의 Refresh) 바뀐다. 감사 기록에는 `device.data_model.refresh`로 남는다.

**요청 타임아웃** (`--usp-request-timeout`, `--usp-full-read-timeout`)
- Controller가 Agent의 응답을 기다리는 시간이다(초 단위 정수). `--usp-request-timeout`(환경 변수 `DHONOMOS_USP_REQUEST_TIMEOUT`, 기본 30)은 일반 요청에, `--usp-full-read-timeout`(`DHONOMOS_USP_FULL_READ_TIMEOUT`, 기본 120)은 **데이터 모델 전체를 읽는 요청**에 쓴다. 후자는 `Device.`를 경로에 포함하는 Get(신규 장비·펌웨어 변경 때의 전체 읽기 `system:bootstrap`, 작업으로 보낸 `Device.` 전체 읽기)과 데이터 모델을 배우는 `GetSupportedDM`(접속 때와 Refresh data model)이다. `Device.DeviceInfo.`처럼 그 아래의 경로는 일반 요청이다.
- 기동 때 검사한다. 0이거나 `--usp-full-read-timeout`이 `--usp-request-timeout`보다 짧으면 오류를 내고 시작하지 않는다.
- 시간 안에 응답이 없으면 요청은 `no response within the timeout`으로 실패하고, 작업이면 대기(pending)로 돌아가 **Agent가 다시 접속하거나 깨울 때** 다시 보낸다. 안정된 MQTT 세션에서는 며칠 뒤일 수 있다. CPU가 느린 장비가 부팅 직후에 큰 응답을 만드느라 기본값을 넘기는 경우(예: 400 MHz CPU가 192 KB GetResp에 66초)에는 `--usp-full-read-timeout`을 올린다. 일반 요청이 자주 시간 초과가 나는 Agent가 있으면 `--usp-request-timeout`을 올리되, 요청 하나가 멈추면 같은 장비의 작업이 그동안 줄을 서므로 너무 크게 잡지 않는다.
- 시간이 지난 뒤 도착한 응답은 버리고 info 로그 `response arrived after the request timed out; dropped`(`agent`, `msg_id`, `timeout_ms`, `late_ms`)를 한 번 남긴다. 최근 256건·10분 안의 시간 초과(와 아래 연결 교체로 끝난 요청)만 기억하므로 그보다 오래된 것은 debug 로그 `response to an unknown request`로만 남는다. 이 info 로그가 보이면 그 요청 종류의 타임아웃이 Agent에게 모자란 것이다.
- **연결 교체 (ADR-109)**: Agent가 새 연결을 맺어(WAN 주소 변경, 회선 전환) 옛 연결을 대체하면(WebSocket·STOMP·내장 MQTT 브로커, 로그 `USP … closed`의 `reason=replaced`), Agent는 옛 연결로 받고 아직 답하지 않은 요청을 옛 연결과 함께 버린다(obuspa 확인). 그 요청은 시간 제한을 기다리지 않고 곧바로 `the connection was replaced before the agent answered`로 실패한다(info 로그 `connection replaced; the requests sent over the old one failed`, 지표 `dhonomos_usp_request_replaced_total`). 새 연결로 보낸 요청은 건드리지 않는다 — 요청마다 보낸 연결의 번호를 기억해, 교체 직후 새 연결로 보낸 요청과 구분한다. 교체는 새 연결이 Record를 받을 수 있게 된 뒤에 알린다(WebSocket은 연결 즉시, STOMP는 SUBSCRIBE 뒤, 내장 MQTT 브로커는 구독하고 응답 토픽을 안 뒤): 그 전에 다시 보내면 버려지거나 거절된다.
  - 작업이면 "연결 끊김"처럼 시도 1회를 쓴다(`max_attempts`가 남았으면 pending, 아니면 그 오류로 실패). 다만 Agent가 새 연결로 붙어 있으므로 다음 접속을 기다리지 않고 **바로** 새 연결로 다시 보내고, 뒤 작업도 이어서 보낸다. 시도 횟수가 되풀이를 막는다.
  - 실행은 됐는데 응답만 잃은 비멱등 요청(Set·Operate 등)이 다시 나갈 수 있다(연결 끊김 뒤 재시도와 같은 수준). 다시 나가면 안 되는 작업(펌웨어 `Download` 등)은 `max_attempts`를 1로 한다.
  - 교체 뒤에 새 연결로 도착한 그 요청의 응답은 버리고 info 로그 `response arrived after the connection the request was sent over was replaced; dropped`를 한 번 남긴다(기억 한도는 시간 초과와 같다). 외부 MQTT 브로커의 토픽으로 보낸 요청은 연결을 구분할 수 없어 시간 제한을 따른다.

## 4f-1. 부팅 때 펌웨어 이미지 다시 읽기 (ADR-108)
장비가 부팅을 알리면(USP `Boot!` 알림, CWMP Inform의 `1 BOOT`) 그 장비의 `Device.DeviceInfo.FirmwareImage.` 아래를 GetParameterValues 하나로 다시 읽는다. U-Boot가 새 이미지로 두 번 부팅에 실패해 이전 이미지로 돌아가면(fallback) 장비는 같은 버전으로 올라오고 `FirmwareUpdated`도 false여서, 버전 변경이나 첫 접속에 하는 전체 읽기가 일어나지 않는다. 이 읽기가 각 이미지의 `Version`·`BootFailureLog` 같은 값을 서버에 반영한다(장비 화면의 Parameters). 읽기로 바뀐 값은 `parameter_change` 이벤트로 남지 않는다 — 그 이벤트는 장비가 보낸 VALUE CHANGE 알림에만 만든다.
- **대상**: 저장된 파라미터에 `Device.DeviceInfo.FirmwareImage.`로 시작하는 경로가 이미 있는 장비(전체 읽기에서 그 객체를 본 장비)만. 그 객체가 없는 장비와 TR-098(`InternetGatewayDevice.`) 장비는 하지 않는다(부팅마다 실패 작업이 쌓이지 않게).
- **전체 읽기와 겹칠 때**: CWMP는 그 Inform이 첫 접속·`0 BOOTSTRAP`·펌웨어 변경이면 하지 않는다(전체 읽기가 같은 값을 가져온다). USP는 같은 장비의 `Device.` 읽기가 큐에서 대기·실행 중이면 하지 않는다(공장 초기화 Boot!가 만든 읽기, 운영자의 Refresh). 다만 USP의 Boot!가 접속 절차(버전 비교)보다 먼저 처리되면 아직 전체 읽기가 큐에 없어 둘 다 들어간다 — 작은 읽기 하나가 더 나갈 뿐이다.
- **작업**: 우선순위 -10, 작성자 `system:boot`, 멱등 키 `boot-fwimage:<장비 ID>:<부팅 식별자>`. 식별자는 CWMP에서 Inform의 `CurrentTime`, USP에서 Boot! Notify의 `msg_id`다. 재전송된 Inform·Notify는 같은 부팅이라 작업을 더 만들지 않는다. 시계가 맞지 않아 부팅마다 같은 `CurrentTime`을 보내는 CWMP 장비나 `msg_id`를 되풀이하는 USP Agent는 두 번째 부팅부터 읽히지 않는다.
- **비용**: 장비 한 대 부팅당 GetParameterValues 하나(LS500X 기준 약 16개 파라미터).
- **하지 않는 것**: fallback을 알람이나 이벤트로 따로 해석하지 않는다(`BootFailureLog` 형식이 벤더마다 다르다). 운영자는 장비 화면의 FirmwareImage 값으로 본다. USP 자동 구독을 끄면(`--usp-auto-subscribe=false`) `Boot!`가 오지 않으므로 이 읽기도 없다.

## 4g. CPE 인증, 장비별 자격증명, Connection Request 보안
자체 보안 점검(M-4, L-1, L-3~L-6)의 CWMP 쪽 수정이다.

**Digest 인증 (`--cpe-auth digest`)**
- nonce는 챌린지마다 새로 만들어 **그 챌린지를 받은 주소**(IPv6는 /64)에서만 쓸 수 있다. 요청 하나(nonce와 nc)는 한 번만 받는다 — 같은 `Authorization` 헤더를 다시 보내면 거절한다. 요청 대상(`uri`)이 맞지 않아도 거절한다.
- nonce가 만료됐거나 nc를 이미 썼는데 비밀번호가 맞으면 `stale=true`가 붙은 새 챌린지를 돌려준다. CPE는 비밀번호를 다시 묻지 않고 새 nonce로 다시 시도한다. 이 응답은 인증 실패로 세지 않는다(`--cpe-auth-failure-limit`).
- `--cpe-digest-no-qop`(`DHONOMOS_CPE_DIGEST_NO_QOP`, 기본 true): `qop` 없는 RFC 2069 응답을 받는다. 챌린지는 항상 `qop="auth"`를 제안하므로 현대적인 스택은 쓰지 않는다. 이 방식은 클라이언트 nonce·nc가 없어 재생을 막을 수 없다. 플릿의 모든 모델이 `qop=auth`로 인증하는 것을 확인한 뒤 `false`로 한다(`dhonomos_cwmp_http_responses_total{status="401"}`가 늘면 되돌린다).
- `--cpe-digest-bind-client`(`DHONOMOS_CPE_DIGEST_BIND_CLIENT`, 기본 true): nonce를 챌린지를 받은 주소에 묶는다. ACS가 여러 프록시 뒤에 있어 챌린지와 응답의 출발 주소가 다를 수 있으면 `false`.

**장비별 ACS 자격증명 (`--acs-auth-per-device`)**
- 공용 자격증명은 장비 신원을 증명하지 않는다(위협 모델 "공용 자격증명이 주지 않는 것"). 자격증명 발급은 **장비마다 한 번**이다: 발급 중인 자격증명은 어느 세션도 바꾸지 못하고(같은 것을 다시 보낼 뿐), 이미 장비에 적용된 것도 세션이 바꾸지 못한다.
- `--onboarding quarantine`에서는 장비를 active로 바꾸기 전에는 발급하지 않는다. active로 바꾼 뒤 그 장비의 다음 Inform에서 발급한다. `preregistered`는 사전 등록(active)된 장비의 첫 Inform에서 발급한다. 승인하기 전에 장비 상세의 마지막 접속 주소·OUI·시리얼이 기대와 맞는지 확인한다.
- 다시 발급하려면(공장 초기화, 교체) `DELETE /api/v1/devices/{id}/credentials/acs_auth`로 지운다. 진행 중이던(pending) 자격증명도 함께 지워진다. 다음 BOOTSTRAP(quarantine·preregistered는 다음 Inform)에서 새로 발급한다. `connection_request`도 같다.
- 장비가 새 자격증명을 적용했는데 확인 응답이 유실돼 pending으로 남았으면, 장비는 현재 것과 pending 중 어느 쪽 비밀번호로도 접속할 수 있다. pending으로 접속하면 그것이 현재 자격증명이 된다.
- **장비가 자격증명 SetParameterValues를 SOAP Fault로 거부하면**(SPV는 원자적이라 아무것도 적용되지 않는다) 로그에 WARN `per-device credentials refused by the CPE; provisioning again on the next trigger`(`device`, `what`, `fault`; 비밀번호는 남기지 않는다)가 남고, 작업은 `failed`(오류가 `9003 …`처럼 fault 코드로 시작)로 끝난다. pending 자격증명은 두었다가 **다음 trigger(새 장비·BOOTSTRAP·펌웨어 변경)에서 버리고 새 비밀번호로 다시 발급**한다. `preregistered`/`quarantine`의 Inform 경로는 거부된 지 **24시간이 지나야** 다시 보낸다(거부하는 장비에 Inform마다 SPV를 보내지 않으려는 것이다). 운영자가 `DELETE .../credentials/<종류>`로 지우면 기다리지 않고 다음 Inform에 바로 발급한다. 세션 유실·타임아웃·만료처럼 **장비의 Fault가 아닌 실패**는 장비가 적용했을 수 있어 pending을 그대로 두고 다시 발급하지 않는다. 이 처리 이전에 거부당해 멈춘 장비(pending이 있고 그 작업이 Fault로 실패)도 같은 규칙으로 풀린다.

**CPE가 올리는 파라미터 상한**
- 이름이 `Device.` 또는 `InternetGatewayDevice.`로 시작하는 것만 저장한다.
- `--cpe-max-params-per-message`(`DHONOMOS_CPE_MAX_PARAMS_PER_MESSAGE`, 기본 50000): Inform, GetParameterValues·GetParameterNames 응답 하나에서 저장하는 수. `--cpe-max-params-per-device`(`DHONOMOS_CPE_MAX_PARAMS_PER_DEVICE`, 기본 100000): 장비 하나가 가질 수 있는 수. 한도를 넘는 새 파라미터는 저장하지 않고 센다 — 이미 있는 파라미터는 계속 갱신되고 CPE 세션은 정상 진행한다.
- 지표 `dhonomos_cwmp_params_rejected_total{reason="path"|"message_limit"|"device_limit"}`가 늘면 로그의 `dropping parameters the CPE reported beyond the limits`(세션당 한 번 WARN)에서 장비를 찾는다. 대형 게이트웨이(호스트·Wi-Fi 클라이언트 표가 큰 것)가 정상적으로 넘으면 값을 올린다.

**Connection Request**
- **`--cr-deny`로 ACS 서버가 있는 내부 대역을 막는다.** CPE가 보고한 Connection Request URL로 ACS가 GET을 보내므로, 사설 대역을 쓰는 CPE 관리망을 허용하는 기본값에서는 CPE가 ACS 내부망의 HTTP 서비스를 가리킬 수 있다(SSRF). 기본값은 사설 대역(RFC 1918, CGNAT 100.64.0.0/10, ULA)을 막지 않는다 — CPE가 그 대역에 있는 ISP가 많기 때문이다. 그래서 운영자가 서버 쪽 대역을 명시한다. 예: `--cr-deny 10.0.0.0/24,10.0.1.0/24,192.168.100.0/24`(ACS·DB·브로커·API가 있는 서브넷, 관리망, 모니터링). 환경 변수 `DHONOMOS_CR_DENY`, 쉼표 구분. 루프백·링크 로컬(169.254.0.0/16, 클라우드 메타데이터 포함)·멀티캐스트는 기본으로 막혀 있다. CPE 대역이 정해져 있으면 `--cr-allow`로 그 대역만 허용하는 편이 더 단단하다. 판정은 이름을 해석한 IP로 하므로 DNS 이름으로 우회할 수 없다(ADR-053).
- 대상이 `401 Basic`을 요구해도 기본으로 CR 비밀번호를 보내지 않는다(평문 http이기 때문). 로그·작업 응답에 `failed: the CPE asks for Basic authentication over plain http, which is not allowed`가 보이면 그 장비의 Connection Request 인증 설정을 Digest로 바꾸는 것이 맞다. 정말 Basic만 되는 CPE가 있으면 `--cr-basic-auth`(`DHONOMOS_CR_BASIC_AUTH`)로 켠다. 전체 CPE에 적용되고, 그 CPE나 그 주소에서 응답하는 누군가가 비밀번호를 평문으로 받는다는 뜻이다.

## 4g-1. STUN: NAT·CGNAT 뒤 CPE의 UDP Connection Request (TR-111)
CPE가 STUN 서버에 바인딩을 보내 자기 UDP 주소를 알리면, ACS가 그 주소로 UDP Connection Request를 보낸다(ADR-040). 전달 확인은 없다(`sent over UDP`). XMPP(4h)를 쓸 수 없는 장비의 대안이다.

**켜기**
- `--stun-listen 0.0.0.0:3478`(`DHONOMOS_STUN_LISTEN`)과 `--stun-public-address host[:port]`(`DHONOMOS_STUN_PUBLIC_ADDRESS`, 장비가 접속할 주소. 포트를 빼면 `--stun-listen`의 포트). 후자는 `--files-secret`을 요구한다 — 장비별 STUN 비밀번호가 `--files-secret`과 장비 ID에서 유도되므로 **`--files-secret`은 바꾸지 않는다**(바꾸면 장비가 가진 비밀번호가 맞지 않아 바인딩을 받지 않는다. 장비의 비밀번호는 읽어 올 수 없어 ACS가 알아채지 못한다).
- 방화벽: 3478/udp. UDP Connection Request도 `--cr-allow`/`--cr-deny` 정책을 거친다(장비 UDP 주소가 허용 대역에 없으면 `failed: UDP connection request: address not permitted: <주소>`). 셀룰러 장비의 공인 주소가 정책에 들어 있어야 한다.
- 깨우기 순서: XMPP 세션이 있으면 XMPP(4h), 없으면 HTTP Connection Request URL이 사설·CGNAT·루프백·링크 로컬 주소이고 UDP 주소를 아는 장비는 **HTTP를 건너뛰고 STUN 소켓에서 UDP**로 보낸다. URL이 공인 주소이면 HTTP를 먼저 하고 실패하면 UDP로 간다. UDP 주소는 인증된 STUN 바인딩(MESSAGE-INTEGRITY가 맞는 것)과 Inform의 `ManagementServer.UDPConnectionRequestAddress`로 학습한다.

**장비 설정**
- 설정하는 값: `Device.ManagementServer.STUNEnable=true`, `STUNServerAddress`(=host), `STUNServerPort`, `STUNUsername`(=장비 ID), `STUNPassword`(유도한 값)를 한 번의 SetParameterValues로, `UDPConnectionRequestAddress`의 능동 알림(2)을 SetParameterAttributes로. 두 작업은 `system:stun`이 만든 것으로 작업 목록에 보인다. `STUNPassword`는 작업의 비밀값(secret)이다: `--secrets-key`가 있으면 큐에 암호화해 저장하고, API·UI에는 `********`로 보이며, 장비가 받아들인 뒤 저장 파라미터에는 빈 값으로 남는다(키가 없으면 큐에만 평문). 0030 이전 버전이 남긴 평문은 마이그레이션 0030이 지운다.
- **새 장비·BOOTSTRAP·펌웨어 변경(zero-touch)**: 전체 트리를 읽을 때 함께 보낸다.
- **이미 등록된 장비는 다음 Inform에서**: STUN 서버를 켜기 전에 등록된 장비는 다시 BOOTSTRAP하지 않고(icwmp는 ACS URL을 바꿔도 BOOTSTRAP하지 않는다) 펌웨어도 드물게 바꾸므로 zero-touch만으로는 영영 설정되지 않는다. STUN 서버를 켠 ACS는 **active인 TR-181(`Device.`) 장비가 Inform할 때마다** 저장된 파라미터를 비교해, 장비가 STUN 파라미터를 가지고 있는데(저장된 `Device.ManagementServer.STUNEnable`이 있다) `STUNEnable`≠true, `STUNServerAddress`·`STUNServerPort`·`STUNUsername`이 설정과 다르거나 저장된 값이 없으면 위 설정을 보낸다. `STUNPassword`는 장비가 읽어 주지 않으므로 비교하지 않고, 알림 속성은 저장하지 않으므로 비교하지 않는다(설정을 보낼 때 함께 간다). 이 경로는 `auto`·`preregistered`·`quarantine`(운영자가 active로 바꾼 뒤) 모두 같다. 장비별 ACS·CR·XMPP 자격증명(4g, 4h)과 달리 운영자의 승인을 더 기다리지 않는다: STUN 비밀번호는 발급하는 자격증명이 아니라 유도한 값이고 장비 자신의 UDP 주소 바인딩만 인증하며, 장비가 잠기거나 ACS에 접근할 길이 생기지 않는다.
- **한 번만 보낸다**: 작업의 키가 (장비, 설정 호스트·포트·장비 ID)의 해시라서 같은 설정은 한 번 보내고, Inform마다 다시 보내지 않는다. 설정이 성공한 뒤 장비가 다른 값을 보고해도(운영자가 바꿨거나 장비가 다르게 되돌려 쓴다) 같은 설정은 다시 보내지 않는다. `--stun-public-address`를 바꾸면 새 설정이므로 다음 Inform에 다시 보낸다(옛 주소로 되돌려도 마찬가지로 장비를 되돌린다). 이미 보낸 작업이 대기 중이거나 실행 중이면 또 만들지 않는다. 같은 세션에 같은 작업이 두 번 가지 않는다(zero-touch가 보낸 세션에는 이 경로가 보내지 않는다).
- **실패하면 24시간 쉰다**: 장비가 STUN 설정을 SOAP Fault로 거부하면(쓰기 불가 9008, 없는 파라미터 9005, 값 오류 9007 등; zero-touch가 보낸 것도 포함) 또는 이 경로가 보낸 작업이 세션 유실 등으로 실패하면, 그 장비에는 **24시간 동안 이 경로로 다시 보내지 않는다**(zero-touch 트리거는 기다리지 않고 보낸다). 24시간이 지난 Inform에서 한 번 더 시도하고(새 작업), 같은 설정을 최대 30번 시도하면 멈춘다(`--stun-public-address`를 바꾸면 새로 시작한다). 쓰기 불가로 저장된 STUN 파라미터(GetParameterNames로 확인된 것)가 있거나 `STUNEnable`을 보고하지 않는 장비(STUN 클라이언트가 없는 장비, TR-098 장비)는 처음부터 보내지 않는다.
- 로그: 보낼 때 INFO `queued the STUN setup for a device that does not have it`(`device`, `round`: 0이 첫 시도). 비교 결과 보내지 않을 때는 DEBUG `STUN parameters differ from the setup, but not sending it now`(`why`: 대기 중, 최근 거부, 이미 보냄). 켜고 처음 기동하면 STUN 파라미터가 있는 기존 장비가 **각자의 다음 Inform**에서 설정을 받으므로(장비당 INFO 한 줄), 장비가 수천 대면 Inform 주기에 걸쳐 나뉘어 나간다.
- 한계: ACS는 장비가 `UDPConnectionRequestAddress`의 능동 알림을 잃었는지, `STUNPassword`가 맞는지 알 수 없다. 장비가 바인딩을 보내는데 `dhonomos_stun_bindings_total`이 늘지 않으면 비밀번호(`--files-secret`이 바뀌었는지)를 의심한다. 공장 초기화는 BOOTSTRAP이라 zero-touch가 설정을 다시 보낸다.

## 4h. XMPP 서버: NAT·CGNAT 뒤 CPE의 Connection Request
셀룰러(CGNAT) 뒤 CPE에는 HTTP Connection Request가 닿지 않는다. 내장 XMPP 서버(TR-069 Annex K, ADR-104)에는 CPE의 `xmppc`가 먼저 접속해 연결을 유지하고, ACS는 그 연결로 Connection Request를 보낸다. 장비가 `iq result`로 답하므로 **전달이 확인된다**. 다른 XMPP 서버가 필요 없고, 장비 계정은 Dhonomos가 만든다. 장비끼리 말할 길은 없다(서버는 장비가 다른 JID로 보낸 stanza를 `service-unavailable`로 거절하고, roster·메시지 전달·서버 간 연동·압축·스트림 관리를 하지 않는다).

**켜기**
- `--xmpp-listen 0.0.0.0:5222`(`DHONOMOS_XMPP_LISTEN`)과 함께 **모두** 필요하다: `--xmpp-domain`(JID domain, 예 `acs.example.net`), `--xmpp-tls-cert`·`--xmpp-tls-key`(PEM, 환경 변수 `DHONOMOS_XMPP_DOMAIN`, `DHONOMOS_XMPP_TLS_CERT/KEY`), `--secrets-key`(장비별 비밀번호를 암호화해 저장). 하나라도 빠지면 기동 오류. 평문 XMPP는 받지 않는다: STARTTLS가 필수이고, TLS 위에서만 SASL PLAIN 하나를 광고한다(SCRAM은 요구하는 장비가 생기면 추가).
- 선택: `--xmpp-keepalive`(기본 30초, 장비에 `KeepAliveInterval`로 설정), `--xmpp-idle-timeout`(기본 `3 × keepalive + 30`초 = 120초: 이 시간 동안 아무것도 오지 않은 연결을 닫는다), `--xmpp-max-connections`(기본 50000), `--xmpp-max-connections-per-ip`(기본 1024, IPv6는 /64; CGNAT 한 주소 뒤에 장비가 많으므로 넉넉히. 0은 끔).
- **인증서 이름 규칙**: 인증서 SAN(DNS)에 `--xmpp-domain`이 있어야 한다(`*.example.net`은 한 단계만). 없으면 기동하지 않는다. 장비는 시스템 CA 번들로 서버 인증서를 검증하고, 호스트 이름과 SNI는 JID domain이다. ACS와 같은 이름·인증서를 쓰면 인증서 하나로 끝난다(권장). 인증서 파일은 1분마다 다시 확인한다(`dhonomos_tls_reload_total{listener="xmpp"}`).
- **방화벽: 5222/tcp**를 연다(예 `ufw allow 5222/tcp`). 장비는 `_xmpp-client._tcp.<domain>` SRV를 먼저 찾고, 없으면 `<domain>:5222`로 간다(DuckDNS처럼 SRV를 못 만드는 DNS도 이 경우다). 이 단계는 `<domain>:5222`만 지원한다. 다른 포트·호스트는 `ServerTable` 설정이 필요하다(2단계).
- **단일 프로세스**: 장비 연결은 프로세스 메모리에 있으므로 XMPP 서버와 Waker(API의 깨우기, 잡의 깨우기)가 같은 프로세스여야 한다. `--role all`로 돌린다. `--role api`는 XMPP를 돌리지 않는다: 그 프로세스의 깨우기는 XMPP를 쓰지 못하고 HTTP·UDP로 가며, 기동 때 WARN이 남는다(`--xmpp-listen`을 줘도 무시한다). `--role acs`에 XMPP를 켜도 다른 프로세스의 API는 쓰지 못한다. 수평 확장은 USP처럼 로드맵 OP-03이다. 프로세스를 다시 시작하면 연결이 모두 끊기고 장비가 다시 접속한다(시작할 때 `xmpp_connected_at`을 모두 지운다).

**장비 설정(zero-touch)**
- 대상은 데이터 모델 루트가 `Device.`(TR-181)이고 저장된 파라미터에 `Device.XMPP.`가 있는 장비다. TR-098 장비는 하지 않는다. 시점은 장비별 CR·ACS 자격증명과 같다(`auto`: 새 장비·BOOTSTRAP·펌웨어 변경, `preregistered`/`quarantine`: 운영자가 받아들인 장비 중 아직 XMPP 자격증명이 없는 장비의 다음 Inform). Inform에는 `Device.XMPP.`가 없으므로 **새 장비는 전체 트리를 읽은 직후 같은 세션에서** 설정한다(이미 아는 장비는 다음 Inform 때 저장된 트리를 보고). BOOTSTRAP 없이 접속하는 장비(예: ACS 주소만 바꾼 `preregistered` 장비)는 전체 트리를 읽지 않으므로, 승인된 장비의 다음 Inform에서 `Device.XMPP.`만 한 번 읽어 확인한 뒤 같은 세션에서 이어 간다(그 객체가 없는 장비는 오류로 끝나고 다시 묻지 않는다).
- 한 번의 SetParameterValues(원자적)로 `Device.XMPP.Connection.{i}.`의 `Username`(=장비 ID, JID는 `<장비 ID>@<domain>`)·`Password`(24자 무작위, 암호화 저장·작업에도 암호화)·`Domain`·`Resource`(비움: 서버가 `cwmp-<무작위>`를 줌)·`UseTLS=true`(명시)·`ServerConnectAlgorithm=DNS-SRV`·`KeepAliveInterval`·`ServerRetryInitialInterval=10`·`ServerRetryIntervalMultiplier=2000`·`ServerRetryMaxInterval=1800`·`Enable=true`(마지막 값)와 `Device.ManagementServer.ConnReqXMPPConnection`·`ConnReqAllowedJabberIDs=acs@<domain>`을 설정한다. 재시도 back-off(접속 실패 때 10초에서 시작해 두 배씩, 최대 1800초)를 명시하는 이유: 장비의 xmppc는 펌웨어를 올려도 자기 설정을 유지해 옛 이미지에서 올라온 장비는 1/1000/1(실패하면 1초마다 영원히 재시도)을 그대로 갖고 있기 때문이다. 값은 펌웨어 쪽 xmppc의 새 기본값과 같다.
- **값의 타입**: 장비는 타입이 다른 값이 하나라도 있으면 `9003 … 9006 Invalid parameter type`으로 SPV 전체를 거부한다. 그래서 각 값은 **그 장비가 저장된 파라미터에서 보고한 타입**(`device_params.xsd_type`)을 우선 쓰고, 보고한 적이 없거나 비어 있으면 TR-181 타입을 쓴다: `Enable`·`UseTLS` boolean, `KeepAliveInterval` **long**, `ServerRetry*` unsignedInt, 나머지 string. 방금 AddObject로 만든 연결은 아직 보고된 값이 없어 TR-181 타입으로 나간다.
- `Device.XMPP.Connection.{i}.`이 없으면 먼저 AddObject를 보내고, 장비가 답한 번호로 **같은 세션에서** 이어서 설정한다. 이미 있으면 이 장비 계정이 든 행, 없으면 `Domain`이 `--xmpp-domain`인 행(대소문자·끝의 점 무시), 없으면 `Username`이 빈 행 순서로 가장 낮은 번호를 쓴다. 장비를 지우고 다시 등록하면 `Connection.1`에 옛 계정이 우리 domain과 함께 남는데, `Connection.1`만 쓰는 펌웨어는 새 행으로는 접속하지 않으므로 그 행을 다시 쓴다. domain이 다르고 `Username`이 있는 연결은 운영자의 다른 용도로 보고 건드리지 않으며(새 연결을 추가한다) 그대로 둔다.
- 비밀번호는 장비가 처음 그 비밀번호로 로그인할 때 확정된다(`xmpp_pending` → `xmpp`). 발급은 **장비당 한 번**이고 세션이 바꾸지 못한다. 다시 발급(공장 초기화, 탈취 의심)하려면 `DELETE /api/v1/devices/{id}/credentials/xmpp`로 지운다(진행 중인 pending도 함께). 다음 trigger에서 새로 발급한다. 같은 이름으로 접속 중인 세션은 새 로그인이 `conflict`로 밀어낸다(계정당 세션 하나).
- **장비가 SetParameterValues(또는 AddObject)를 SOAP Fault로 거부하면** 4g의 규칙과 같다: WARN `per-device credentials refused by the CPE; provisioning again on the next trigger`(`what=XMPP`), pending은 다음 trigger(새 장비·BOOTSTRAP·펌웨어 변경)에서 버리고 새 비밀번호·새 작업으로 다시 발급한다. `preregistered`/`quarantine`의 Inform 경로(와 `Device.XMPP.` 한 번 읽기)는 거부된 지 24시간이 지나야 다시 시도하고, 운영자가 `DELETE .../credentials/xmpp`로 지우면 바로 시도한다. 세션 유실·타임아웃 같은 Fault가 아닌 실패는 pending을 그대로 둔다.
- XMPP로 보내는 Connection Request는 장비의 **CR 사용자 이름·비밀번호**를 쓴다: 장비별 CR 자격증명(`--cr-per-device`)이 있으면 그것, 없으면 공용 `--cr-username/--cr-password`. 둘 다 없으면 XMPP로 보내지 않고 HTTP·UDP로 간다.

**깨우기 순서**: 장비가 XMPP로 연결되어 있으면 **XMPP를 먼저** 쓴다(전달 확인, NAT 무관, `--cr-allow`/`--cr-deny` 주소 정책을 거치지 않음). 10초 안에 `result`가 없거나 연결이 없으면 HTTP → UDP로 간다. 장비가 `error`(`not-authorized` 등)로 답하면 같은 자격증명을 쓰는 다른 경로도 소용없으므로 넘어가지 않고 `failed: XMPP connection request refused: <condition>`이다. 성공은 `sent over XMPP`(`dhonomos_connection_requests_total{outcome="sent_xmpp"}`).

**keep-alive의 데이터 비용**: 장비가 `KeepAliveInterval`마다 ping을 보낸다(TLS 포함 왕복 약 400 B). 30초는 장비당 월 약 35 MB, 120초 약 9 MB, 300초 약 3.5 MB다. 종량제 회선이면 `--xmpp-keepalive`를 늘리되, 통신사 NAT가 유휴 TCP 매핑을 끊는 시간보다 짧아야 연결이 유지된다. 바꾸면 이미 설정된 장비에는 반영되지 않는다(`KeepAliveInterval`을 직접 바꾼다).

**장비별로 어떻게 깨울 수 있고 마지막에 어떻게 깨웠는지 보기** (HTTP·XMPP·STUN/UDP 공통)
- **UI**: CWMP 장비 상세의 "Connection request" 카드에 HTTP Connection Request URL, XMPP 세션(시작 시각과 JID), STUN/UDP 주소(마지막 확인 시각), 장비가 광고하는 방식(저장된 `ManagementServer.SupportedConnReqMethods` 값 — **장비가 보고한 값일 뿐** Dhonomos는 그 방식이 실제로 되는지 확인하지 않는다), 마지막 깨우기(시각·방식·결과)가 있고, "Send connection request" 버튼도 여기 있다. 장비 목록에서는 XMPP 세션이 있는 장비에 `XMPP` 배지가 붙고, "XMPP connected" 체크로 그런 장비만 볼 수 있다(`?xmpp=1`).
- **API**: 장비 JSON(목록·상세)의 `xmpp_jid`(세션의 전체 JID. XMPP 서버를 돌리는 프로세스의 API에서만 값이 있고, `--role api`처럼 서버가 없는 프로세스에서는 연결 중이어도 `null`), `udp_cr_address`·`udp_cr_seen_at`(UDP Connection Request 주소와 마지막 확인 시각), `last_wake_at`·`last_wake_method`·`last_wake_outcome`. `last_wake_method`는 요청이 실제로 나간 방식(`xmpp`·`http`·`udp`·`usp`)이고, 아무것도 보내지 않았으면(URL 없음, 실패, 오프라인 USP Agent) `null`이다. `last_wake_outcome`은 깨우기 응답과 같은 문구(`sent over XMPP`, `sent`, `failed: ...`)다. `POST /devices/{id}/connection-request`와 작업 생성·잡이 하는 깨우기를 모두 기록한다(깨울 때마다 UPDATE 한 번이고, 기록이 실패해도 깨우기는 그대로다).
- **필터**([장비 필터](filters.md)): `xmpp_connected = true`(지금 XMPP 세션이 있는 장비), `udp_cr = true`(UDP CR 주소를 아는 장비). 예: `protocol = cwmp and xmpp_connected = false and udp_cr = false`는 HTTP로만 깨울 수 있는 CWMP 장비다.

**연결 상태와 보호**
- 장비 JSON의 `xmpp_connected_at`: 지금 XMPP 세션이 시작된 시각, 없으면 `null`. 연결(bind)과 끊김 때만 기록한다(ping마다 쓰지 않는다).
- 인증 전 연결은 30초 안에 resource bind까지 끝내야 하고(아니면 `connection-timeout`), 그 전에는 stanza 4 KiB까지만 받는다(이후 64 KiB). XML은 DTD·주석·처리 명령·엔티티를 받지 않는다(`restricted-xml`). 로그인 실패는 (장비, 주소) 쌍 5회·장비 50회·주소 60회까지 15분 안에 센다. 넘으면 `not-authorized`로 닫는다(xmppc의 재접속 폭주도 여기 걸린다). 읽지 않는 장비는 쓰기 대기열 256 KiB를 넘으면 닫는다.
- 로그에는 stanza 이름과 오류 조건만 남고, 비밀번호·CR 자격증명·stanza 본문은 남지 않는다.

**지표**: `dhonomos_xmpp_connections`(bind된 세션 수), `dhonomos_xmpp_auth_total{result="ok|fail|locked"}`, `dhonomos_xmpp_stream_errors_total{condition}`(`not-well-formed`·`restricted-xml`·`policy-violation`·`connection-timeout`·`conflict`·...), `dhonomos_xmpp_refused_connections_total{reason="connections_total|connections_per_ip"}`, `dhonomos_xmpp_tls_handshake_failures_total`, `dhonomos_xmpp_connection_requests_sent_total`.

**문제 해결**
- 장비가 접속하지 못한다: `xmppc`의 `UseTLS`와 시스템 CA 번들(인증서 발급자), 인증서 SAN에 JID domain이 있는지, `_xmpp-client._tcp.<domain>` SRV 또는 `<domain>:5222`, 방화벽 5222/tcp. `dhonomos_xmpp_tls_handshake_failures_total`이 늘면 인증서를 의심한다.
- `dhonomos_xmpp_auth_total{result="fail"}`: 장비의 `Password`가 ACS의 것과 다르다(공장 초기화·수동 변경). `DELETE .../credentials/xmpp` 뒤 다음 trigger에서 새로 발급한다. `locked`가 늘면 같은 장비·주소가 계속 틀리는 중이다.
- 깨우기가 HTTP로 가는데 `xmpp_connected_at`이 있다: `--role api` 프로세스가 깨우고 있다(위 단일 프로세스. 이때 `xmpp_jid`도 `null`이다). 또는 장비가 10초 안에 답하지 않는다(`dhonomos_xmpp_connection_requests_sent_total`은 늘고 `sent_xmpp`는 그대로). 장비의 `last_wake_method`가 `http`이면 XMPP로 가지 않은 것이다.

## 5. 보존 기간
| 데이터 | 기본 | 플래그 |
|---|---|---|
| 장비 이벤트(Inform마다 1건) | 30일 | `--events-retention-days` |
| 끝난 작업 | 90일 | `--tasks-retention-days` (`once` 프리셋 기록은 유지) |
| 해제된 알람·끝난 사일런스 | 90일 | `--alarms-retention-days` |
| 시계열 원본 / 전체 | 2일 / 30일 | `--metrics-raw-days` / `--metrics-retention-days` |
| 감사 로그 | 무기한 | — |

0은 무기한. 정리는 1시간마다 1만 행씩 나눠 지운다(ADR-052).

## 6. 모니터링
- `GET /healthz`(인증 없음) — 살아 있음. `GET /metrics` — Prometheus 형식(viewer 이상 계정·API 키).
- 볼 지표:

| 지표 | 의미 / 경보 예 |
|---|---|
| `dhonomos_cwmp_informs_total` | 초당 Inform. 평소 대비 급감 → 망·ACS 장애 |
| `dhonomos_cwmp_sessions` | 진행 중 세션. `--acs-max-concurrent`에 붙어 있으면 503으로 거절 중 |
| `dhonomos_cwmp_request_duration_seconds` | ACS 응답 시간. p99 > 1초면 DB 확인 |
| `dhonomos_cwmp_http_responses_total{status="503"}` | 과부하 거절 |
| `dhonomos_cwmp_auth_failures_total`, `dhonomos_cwmp_rejected_total` | 인증 실패·수용 거절(사칭 시도, 잘못된 자격증명) |
| `dhonomos_cwmp_connections`, `dhonomos_cwmp_rejected_total{reason="connections_total"\|"connections_per_ip"\|"body_timeout"}` | 열린 연결 수와 연결 상한(`--acs-max-connections` 기본 20000, `--acs-max-connections-per-ip` 기본 256, 0은 끔)·본문 읽기 시간 초과(60초) 거절. TLS 종단 프록시 뒤라면 주소별 상한을 0으로 |
| `dhonomos_cwmp_connection_timeouts_total{phase}` | 헤더 30초·TLS 핸드셰이크 10초 안에 오지 않은 연결(`header`·`tls_handshake`, 급증하면 slowloris 의심)과 조용해진 keep-alive 연결(`idle`, 평소에도 있음) |
| `dhonomos_cwmp_params_rejected_total{reason}` | CPE가 올린 파라미터를 상한 때문에 저장하지 않은 수. `reason`: `path`(`Device.`·`InternetGatewayDevice.`로 시작하지 않음), `message_limit`(메시지당 상한), `device_limit`(장비당 상한). 늘면 4g |
| `dhonomos_param_store_errors_total{source,kind}` | 파라미터 저장 실패 수. `kind="row"`는 DB가 값 하나를 거절했지만 같은 배치의 나머지는 저장된 경우(예: 값의 NUL 문자), `kind="batch"`는 쓰기 전체가 실패한 경우(DB 불가 등). `source`: `cwmp`·`usp`·`presets`. 늘면 같은 시각의 WARN 로그 `storing parameters failed`(장비 ID, 처음 거절된 경로, DB 메시지; 값은 남기지 않는다)에서 장비와 파라미터를 찾는다 |
| `dhonomos_connection_requests_total{outcome}` | `failed` 비율 상승 → CPE 자격증명·방화벽·주소 정책(`--cr-deny`). `sent_xmpp`는 XMPP로 전달이 확인된 것(4h) |
| `dhonomos_xmpp_connections`, `dhonomos_xmpp_auth_total{result}`, `dhonomos_xmpp_stream_errors_total{condition}` | 내장 XMPP 서버(4h)의 bind된 세션 수, 로그인(`ok`·`fail`·`locked`), 스트림 오류 조건별 수. `fail`·`locked`가 늘면 장비의 비밀번호가 어긋났거나 추측 시도, `policy-violation`·`restricted-xml`은 비정상 클라이언트 |
| `dhonomos_tasks_completed_total{outcome}` | `fault` 증가 → 작업·프리셋 내용 확인 |
| `dhonomos_usp_agents_connected`, `dhonomos_usp_mqtt_connected` | USP 연결 상태(브로커 끊김 = 0) |
| `dhonomos_usp_request_timeouts_total` | Agent 무응답. 같은 Agent의 늦은 응답이 info 로그 `response arrived after the request timed out`로 보이면 타임아웃이 모자란 것이다(4f 요청 타임아웃) |
| `dhonomos_usp_request_replaced_total` | 보낸 연결이 같은 Agent의 새 연결로 교체되어 곧바로 실패시킨 요청 수(ADR-109, 4f 요청 타임아웃). 늘면 Agent의 주소가 자주 바뀌거나(회선 전환) 연결이 자주 다시 맺어지는 것이다. `dhonomos_usp_connections_closed_total{reason="replaced"}`와 함께 본다 |
| `dhonomos_usp_mqtt_broker_connections` | 내장 MQTT 브로커의 열린 연결(CONNECT 이후, EID 확인 전 포함) |
| `dhonomos_usp_mqtt_broker_received_total`, `_sent_total` | Agent가 보낸·Controller가 보낸 Record(PUBLISH) 수 |
| `dhonomos_usp_mqtt_broker_rejected_total{reason}` | 내장 MQTT 브로커가 거절·끊은 연결/패킷. `reason`: `credentials`(공용 계정 불일치), `certificate`·`endpoint_id`(인증서·EID 불일치), `auth_method`·`client_id`(지원 안 하는 확장 인증, 너무 긴 Client ID), `topic`(허용 안 된 토픽), `subscription`(와일드카드·공유 구독), `qos2`·`retain`·`topic_alias`·`protocol`·`malformed`(MQTT 위반), `keep_alive`(무응답), `protocol_version`(3.1.1/3.1 클라이언트), `connect`(CONNECT 제한 시간·잘못된 첫 패킷), `record`(첫 Record를 읽지 못함), `connections_total`·`connections_per_ip`(연결 상한, accept 직후 닫음), `limits`(패킷·필터·속성 크기 상한), `partial_packet`(패킷이 제때 다 오지 않음), `ack_timeout`(Receive Maximum 창이 PUBACK 없이 가득 참) |
| `dhonomos_usp_mqtt_broker_tls_handshake_failures_total` | 내장 MQTT 브로커 TLS 핸드셰이크 실패 |
| `dhonomos_usp_stomp_connections`, `dhonomos_usp_stomp_rejected_total` | 내장 STOMP 브로커의 열린 연결. 거절은 로그인 실패와 크기·헤더 수 상한을 넘은 프레임(로그인 전 8 KiB 포함) |
| `dhonomos_usp_stomp_refused_connections_total{reason}` | STOMP 연결 상한으로 accept 직후 닫은 연결. `reason`: `connections_total`·`connections_per_ip` |
| `dhonomos_usp_send_queue_full_total{mtp}` | Agent가 읽지(확인하지) 않아 송신 큐(64)가 가득 차 전송이 즉시 실패한 횟수. `mtp`: `stomp`·`mqtt`·`ws`. 늘면 해당 Agent가 멈춘 것(연결은 아래 시간 초과로 닫힘) |
| `dhonomos_usp_write_timeouts_total{mtp}` | Agent에 쓰는 일이 제한 시간(30초)을 넘겨 연결을 닫은 횟수. `mtp`: `stomp`·`mqtt`·`ws` |
| `dhonomos_usp_connections_closed_total{mtp,reason}` | 끝난 USP 연결 수, MTP(`ws`·`stomp`·`mqtt`·`ws_client`)와 이유별. 같은 `reason`이 로그 "USP … closed" 줄에 `error`·`connected_secs`와 함께 찍힌다. 주요 이유: `agent_closed`(Agent가 닫음), `eof`(프로토콜 종료 없이 TCP/TLS 끝), `reset`, `tcp_timeout`(서버 TCP keepalive 60 s + 10 s×3이 상대를 못 찾음 — 반쯤 열린 연결), `idle_timeout`(ws 무소식·STOMP heart-beat·MQTT Keep Alive), `write_timeout`, `replaced`(같은 Agent의 새 연결), `revoked`, `closed_by_server`. 전체 목록은 `crates/usp-mtp/src/close.rs` |
| `dhonomos_usp_replies_dropped_total{limit}` | Controller가 NotifyResp·Error 답신을 Agent별(`per_agent`, 32개)·전체(`total`, 8192개) 대기 상한 때문에 버린 횟수 |
| `dhonomos_job_auto_pauses_total` | 캠페인이 실패율 기준으로 멈춤 → UI Jobs |
| `dhonomos_alarms_raised_total`, `dhonomos_alarm_storms_total` | 알람 발생·대량 장애 |
| `dhonomos_webhooks_total{outcome="failed"}` | 웹훅 대상 장애(3회 재시도 후 포기) |
| `dhonomos_alarm_emails_total{outcome="failed"}` | 알람 메일 전송 실패(SMTP 서버·자격증명·TLS 확인) |
| `dhonomos_usp_certificates_issued_total{via}` | 발급한 Agent 인증서 수. `via`: `single`(장비 한 대, `POST /devices/{id}/certificate`), `bundle`(번들). 예상 밖으로 늘면 감사 기록 `certificate.bundle`·`device.certificate.issue` 확인 |
| `dhonomos_tls_reload_total{listener,result}` | 인증서 교체 시도(파일 다시 읽기, USP CA 인증서 재발급). `result="error"`가 늘면 새 인증서를 못 읽거나 발급하지 못하는 중(기존 것을 계속 사용) → 파일·키 일치, `--usp-ca-dir` 확인 |
| `dhonomos_metric_samples_dropped_total` | 오래됐거나 잘못된 BulkData |
| `dhonomos_script_runs_total{outcome="failed"}` | 프로비저닝 스크립트 실패 → 장비 이벤트 `script`의 `error`([스크립트 가이드](scripts.md)) |

전체 목록은 `/metrics` 출력 참고.

트레이스(OpenTelemetry): `--otlp-endpoint http://<collector>:4318/v1/traces`(OTLP/HTTP). 기본으로 요청의 10%를 추적한다(`--otlp-sample-ratio`). 스팬은 `cwmp.request`, `api.request`, `usp.request`, `alarms.evaluate`, `jobs.tick`, `presets.scripts`.

## 6a. 거절 로그와 일일 보안 리포트
인터넷에 열린 리스너(ACS 7547, 파일 서버 7548, XMPP 5222, USP wss 7549, STOMP 61614, MQTT 브로커 8883, STUN 3478/udp)가 거절한 것은 지표(`*_rejected_total` 등)로 세기만 하면 *누가* 그랬는지 알 수 없다. 그래서 거절할 때마다 `info` 로그를 한 줄 남긴다. 형식은 늘 같다.

```
request refused listener=cwmp remote=203.0.113.9:51514 reason=auth_failed username="admin"
connection refused listener=cwmp remote=203.0.113.9:51514 reason=tls_handshake error=received corrupt message of type InvalidContentType
refusals suppressed listener=xmpp remote=2001:db8::5 reason=auth_failed suppressed=12
```

- `connection refused`는 연결 단계(TLS 핸드셰이크, 연결 상한, 스트림 오류), `request refused`는 요청 단계(잘못된 자격증명, 서명이 틀린 링크, 잘못된 첫 프레임)의 거절이다. `remote=`는 출발 IP와 포트(알 수 없으면 IP만, 그것도 모르면 `unknown`)이고 `reason=`은 짧은 토큰이다. `username="..."`은 시도한 이름이다(비밀이 아니다. 64자로 자르고 제어 문자는 이스케이프한다). `error=`는 항상 마지막 필드다.
- `listener`와 `reason`:

| listener | reason |
|---|---|
| `cwmp` (ACS) | `auth_failed`(틀린 자격증명, `username`; 처음 Digest 챌린지는 실패가 아니라서 남기지 않는다), `auth_blocked`(인증 실패로 차단된 주소), `connections_total`·`connections_per_ip`, `tls_handshake`, `tls_handshake_timeout`, `header_timeout`(요청 없이 연결만 한 것), `content_encoding`, `body_timeout`, Inform 거절 `oui`·`not_registered`·`retired`·`credential_mismatch`·`shared_credential`(`oui`·`serial` 포함) |
| `stun` | `invalid`(STUN이 아닌 패킷). 정상 Binding 요청과 MESSAGE-INTEGRITY가 틀린 요청은 CPE가 30초마다 보내므로 남기지 않는다 |
| `files` (파일 서버) | `tls_handshake`, `tls_handshake_timeout`, `bad_signature`(서명이 틀리거나 만료된 링크), `unknown_device`, `device_not_accepted` |
| `xmpp` | `connections_total`·`connections_per_ip`, `tls_handshake`, `tls_handshake_timeout`, `stream_error`(`condition`), `sasl_failure`, `auth_failed`(`username`), `auth_locked` |
| `usp_ws` | `tls_handshake`, `tls_handshake_timeout`, `invalid_endpoint_id`, `certificate_mismatch`, `certificate_revoked`·`certificate_required`·`outranked`(4d) |
| `usp_stomp` | `connections_total`·`connections_per_ip`, `tls_handshake`, `tls_handshake_timeout`, `no_first_frame`, `bad_command`·`bad_version`·`bad_login`(`username` 없음)·`bad_endpoint_id`, `certificate_mismatch`, `certificate_revoked`·`certificate_required`·`outranked`, `bad_frame` |
| `usp_mqtt` | 6장 `dhonomos_usp_mqtt_broker_rejected_total{reason}`와 같은 토큰(`credentials`는 `username` 포함, `certificate`는 `agent`·`certificate` 포함), `tls_handshake`, `tls_handshake_timeout` |
| `usp` | Agent 등록 거절(`oui`·`not_registered`·`retired`·`store`) |

- **같은 (listener, reason, 출발 IP)는 10분에 한 줄만** 남긴다. 그 사이의 반복은 세어 두었다가 다음 줄에 `suppressed=N`으로 붙인다. 다음 줄이 오지 않으면 몇 분 뒤 `refusals suppressed ... suppressed=N` 한 줄로 따로 남는다. 키는 프로세스 전체에서 공유하며 최대 4096개(가장 오래된 것부터 버린다). IPv4-mapped IPv6 주소는 IPv4로 합쳐 센다. **Prometheus 지표는 이전처럼 모든 거절을 센다.**
- 보기: `grep -E 'refused|refusals suppressed' ~/.local/state/dhonomos-dev/dhonomos.log` (파일 로그에는 색 코드가 섞여 있다; 아래 리포트 스크립트는 지운다).
- 성공한 것도 하나씩 남는다: `XMPP login accepted account=… remote=…`, `USP STOMP|MQTT|WebSocket connected agent=… remote=…`. 웹 UI·API 로그인 성공은 서버 로그가 아니라 감사 로그(`auth.login`)에 있고, 틀린 로그인은 `failed login username=… client=…`(warn)이다.

### 일일 보안 리포트: `scripts/security-report.sh`
Dhonomos 로그, Apache 접근 로그, 방화벽 커널 로그에서 지난 24시간(또는 지정한 구간)을 읽어 한 장의 텍스트로 만든다. **읽기 전용이고 sudo가 필요 없다**(Apache 로그와 `journalctl -k`는 `adm` 그룹이면 읽힌다. 못 읽는 부분은 건너뛴다).

```bash
scripts/security-report.sh                              # 지난 24시간, 표준출력
scripts/security-report.sh --since '2026-10-15 09:00' --out /tmp/report.txt
scripts/security-report.sh --known-ips 198.51.100.7,203.0.113.0/24 --wan-if eth0 --lab-nets 10.0.0.0/8
```

옵션: `--since`/`--until`(`date -d`가 읽는 시각), `--out`(디렉터리를 만든다), `--log-dir`(기본 `~/.local/state/dhonomos-dev`의 `dhonomos*.log`), `--apache-dir`(기본 `/var/log/apache2`의 `*access*.log*`, 회전·gz 포함), `--wan-if`(방화벽 로그의 외부 인터페이스, 기본은 없음 = 모든 인터페이스), `--known-ips`(알려진 장비 주소, 기본은 없음), `--lab-nets`(웹 구간에서 뺄 연구실 주소, 기본은 루프백만).

구성: 맨 위 **Attention**(① 알려진 장비 주소가 아닌 곳의 CWMP·XMPP·MQTT·STOMP 인증 실패 ② 연구실 밖에서 UI/API 로그인 성공 ③ 알 수 없는 주소에서 XMPP·USP 로그인 성공 ④ 거절이 100번을 넘은 출발지), 1 거절(listener·reason별 합계, 출발 IP 상위 20과 처음·마지막 시각, 시도한 username 상위 20, 틀린 UI 로그인), 2 눈에 띄는 성공(XMPP·USP 접속, 장비별 자격증명 활성화), 3 웹(외부 IP 상위, 상태 코드, 404 경로 상위, 로그인 POST), 4 방화벽(`UFW BLOCK`의 목적지 포트·출발지 상위). 합계에는 10분 규칙으로 줄이지 않은 반복(`suppressed`)이 들어 있다. 거절 로그는 서버를 재시작한 뒤부터 쌓이므로 그 전 로그에서는 1이 비어 있다.

매일 아침 9시에 파일로 남기려면 crontab에 다음 한 줄을 넣는다(스크립트는 설치하지 않는다. 직접 `crontab -e`로 추가).

```
0 9 * * * /opt/dhonomos/scripts/security-report.sh --out "$HOME/.local/state/dhonomos-dev/security/$(date +\%F).txt"
```

cron에서는 `%`를 `\%`로 써야 한다. 출력 디렉터리는 스크립트가 만들고(권한 700), 파일은 본인만 읽을 수 있다. 종료 코드는 리포트를 썼으면 0이며, Attention 항목이 있어도 0이다.

## 7. 문제 해결
| 증상 | 확인 |
|---|---|
| CPE가 등록되지 않음 | `--onboarding`(quarantine·preregistered), `--allowed-oui`, `dhonomos_cwmp_rejected_total{reason}`, 로그의 `rejected` |
| CPE 인증 실패 | `--cpe-auth`와 CPE의 `ManagementServer.Username/Password`, 장비별 자격증명(`/devices/{id}/credentials`) |
| 장비별 ACS 자격증명 사용 후 공용 비밀번호로 접속하는 CPE가 8001 | 정상 동작: `--acs-auth-per-device`로 장비 자기 자격증명이 확인된 뒤에는 공용이 거부된다. 공장 초기화한 CPE는 관리자가 장비 자격증명을 지우면(`DELETE /api/v1/devices/{id}/credentials/acs_auth`) 다시 공용으로 접속·재발급된다 |
| 장비별 자격증명이 발급되지 않거나 다시 발급되지 않음 | 발급은 장비마다 한 번이다(4g). `quarantine`이면 장비가 active인지, 이미 자격증명이 있으면(`GET /devices/{id}/credentials`) 지워야 다시 발급된다. 발급 작업이 실패한 채 pending이 남았으면 `DELETE .../credentials/acs_auth`가 pending도 지운다 |
| CPE가 Digest 인증을 반복해서 401 | nonce는 요청 한 번(nc)과 챌린지를 받은 주소에만 맞는다. CPE가 같은 nonce·nc를 되풀이하면(`stale=true` 응답을 따르지 않는 스택) 안 된다. 프록시 뒤에서 출발 주소가 바뀌면 `--cpe-digest-bind-client false`, `qop` 없이 응답하는 오래된 스택이면 `--cpe-digest-no-qop true`(기본) |
| CPE가 403을 받음 | 같은 주소에서 인증 실패가 반복돼 10분 차단됨(로그 `blocking a source`, `dhonomos_cwmp_rejected_total{reason="auth_blocked"}`). 자격증명을 고치면 10분 뒤 풀린다. CGNAT 뒤라면 `--cpe-auth-failure-limit 0` |
| CPE가 연결 즉시 끊김 | 같은 주소의 연결이 `--acs-max-connections-per-ip`(기본 256)를 넘었다(`dhonomos_cwmp_rejected_total{reason="connections_per_ip"}`). CGNAT·프록시 뒤라면 값을 올리거나 0 |
| CPE가 8005(Retry request)를 받음 | 그 장비가 분당 세션 상한(`--cpe-session-limit`, 기본 30)을 넘었다(`dhonomos_cwmp_sessions_limited_total`). 대개 Inform을 반복하는 펌웨어 문제다. CPE는 자기 백오프로 다시 접속한다. 정상인데 걸린다면 값을 올린다(0은 끔) |
| 작업이 pending에 머묾 | Connection Request 결과(작업 생성 응답의 `connection_request`). `failed: address not permitted` → `--cr-allow`/`--cr-deny`(ADR-053). NAT 뒤 장비는 STUN 설정 확인 |
| 펌웨어 다운로드가 waiting에서 끝나지 않음 | CPE가 TransferComplete를 보내지 않음 → 24시간 뒤 자동 실패. 파일 서버 주소(`--files-public-url`)가 CPE에서 닿는지 |
| 인증서를 갱신했는데 CPE가 옛 인증서를 봄 | 로그 `TLS certificate reloaded`/`reload failed`, `dhonomos_tls_reload_total`. 이미 열린 연결은 옛 인증서를 유지한다(새 연결부터 바뀜). `--usp-ca-dir`가 발급한 인증서는 만료 7일 전에 자동 재발급(`TLS certificate renewed`/`renewal failed`) |
| USP Agent가 offline | 브로커 계정(dynamic-security), 토픽, `dhonomos_usp_mqtt_connected`; wss면 인증서 SAN의 EID와 `?eid=` 일치(403), 인증서 없는 접속이 인증서로 열린 같은 EID 때문에 409로 거절되는지(`dhonomos_usp_ws_rejected_total`), `eid` 형식(400), `--usp-ws-client-cert required`인데 Agent에 인증서가 없는지 |
| 내장 MQTT 브로커에 접속한 Agent가 보이지 않음 | `RUST_LOG=info,dhonomos_usp_mtp::mqtt_broker=debug`로 `MQTT CONNECT`(Client ID, `usp-endpoint-id`, Request Response Information)·`SUBSCRIBE` 로그와 `dhonomos_usp_mqtt_broker_rejected_total{reason}` 확인. 접속·구독은 됐는데 Agent가 안 나타나면 Agent가 MQTTConnectRecord를 보내지 않는 것이다: Agent 토픽을 `usp/agent/<EndpointID>`로 주거나 `RequestResponseInfo`를 켠다. 같은 EID가 두 장비에 있으면 `Session taken over`(0x8E)로 서로를 끊는다 |
| STOMP·내장 MQTT 브로커 Agent가 접속 즉시 또는 곧 끊김 | 연결 상한: 같은 주소의 연결이 주소별 상한을 넘었다(STOMP `dhonomos_usp_stomp_refused_connections_total{reason}`, MQTT `dhonomos_usp_mqtt_broker_rejected_total{reason="connections_per_ip"}`). NAT·프록시 뒤라면 `--usp-stomp-max-connections-per-ip`·`--usp-mqtt-broker-max-connections-per-ip`를 올리거나 0. 접속 뒤 끊기면 MQTT는 같은 지표의 `limits`(패킷·필터·속성 크기), `partial_packet`(패킷이 60초 안에 다 오지 않음), `ack_timeout`(Agent가 PUBACK을 안 보냄), `keep_alive`; STOMP는 `dhonomos_usp_stomp_rejected_total`(프레임 크기·헤더 수)과 `dhonomos_usp_write_timeouts_total{mtp}`(Agent가 읽지 않음) |
| 알람 웹훅·메일이 오지 않음 | 사일런스 중인지(UI Alarms → Silences), 메일은 `--alarm-email-min-severity` 이상만, `dhonomos_webhooks_total`·`dhonomos_alarm_emails_total`, 로그 `alarm e-mail failed`(debug), HTTPS·STARTTLS면 CA 묶음 마운트 또는 `--smtp-ca` |
| API가 401 | 계정이 하나라도 생기면 API가 닫힌다 — 로그인하거나 API 키(`Authorization: Bearer`) 사용 |

로그 수준은 `RUST_LOG`(예: `RUST_LOG=info,dhonomos_core=debug`). IP 주소를 SNI로 보내는 CPE가 접속할 때마다 rustls가 남기는 경고(`Illegal SNI extension: ignoring IP address presented as hostname`)는 소음이므로 기본으로 `rustls::msgs::handshake=error`를 덧붙여 숨긴다. `RUST_LOG`에 `rustls`가 들어 있으면(예: `RUST_LOG=info,rustls=warn`) 덧붙이지 않는다.

