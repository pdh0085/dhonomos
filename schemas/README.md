# 벤더링된 BBF 데이터 모델·스키마 파일

모두 Broadband Forum 배포본이며 BSD-3-Clause 라이선스입니다. 파일 상단 저작권·라이선스 헤더를 **수정하지 않습니다**.
갱신 시 이 표의 URL·SHA-256을 함께 갱신하고, 루트 `NOTICE`를 확인합니다.

| 파일 | 출처 | 취득일 | SHA-256 |
|---|---|---|---|
| `tr-181-2-21-0-usp-full.xml` | https://usp-data-models.broadband-forum.org/tr-181-2-21-0-usp-full.xml | 2026-10-03 | `3fea104fcae8361c0a2261064921ce09ec76d37c43a7766c2b59ef6c5ccce718` |
| `tr-181-2-21-0-cwmp-full.xml` | https://cwmp-data-models.broadband-forum.org/tr-181-2-21-0-cwmp-full.xml | 2026-10-03 | `08c3005692d27535c75c2a427a9501ce77a8e9fee69dda2037feef43978d8d77` |
| `tr-098-1-8-0-full.xml` | https://cwmp-data-models.broadband-forum.org/tr-098-1-8-0-full.xml | 2026-10-03 | `a5062a88851e80daea64311022cdb1743c4f16074679f12942bd758e450d2de1` |
| `tr-106-types.xml` | https://cwmp-data-models.broadband-forum.org/tr-106-types.xml | 2026-10-03 | `68237466c70b9f48ea647878af65d54c16a42e45d2ef2ba5f6e4a1042e0484a1` |
| `cwmp-1-4.xsd` | https://cwmp-data-models.broadband-forum.org/cwmp-1-4.xsd | 2026-10-03 | `242561acd96a069505bad6b5225713314b21148a3a87bf5c08b6ed7609546f04` |
| `cwmp-1-0.xsd` | https://cwmp-data-models.broadband-forum.org/cwmp-1-0.xsd | 2026-10-03 | `3918026735c84bce51273fbd9c11e5a62881dcba89185d3c17989bc1929e6b7b` |
| `cwmp-1-1.xsd` | https://cwmp-data-models.broadband-forum.org/cwmp-1-1.xsd | 2026-10-03 | `f9ce5ca2e477c215abed6fdfaa4ae331bdaf65fb3a45360c4db90f5cd6fb5fbb` |
| `cwmp-1-2.xsd` | https://cwmp-data-models.broadband-forum.org/cwmp-1-2.xsd | 2026-10-03 | `a555700f3d5cc416f36d8a6b969d3d375404caf1a61c5a66887afc0dcf8c1ca6` |
| `cwmp-1-3.xsd` | https://cwmp-data-models.broadband-forum.org/cwmp-1-3.xsd | 2026-10-03 | `d012e3162c6f4c4da6f72369e39e96aeab85b67ae8fdc74e96f93ab5beea179a` |
| `cwmp-datamodel-1-17.xsd` | https://cwmp-data-models.broadband-forum.org/cwmp-datamodel-1-17.xsd | 2026-10-03 | `ed393ba570426a1944b8ce6985a87b632a2350dc500261769df4dd14cc09bfd5` |

`-full.xml` 변종은 `<import>` 없이 자체 완결되어 있어 단독 로드가 가능합니다.

CWMP SOAP 네임스페이스는 `urn:dslforum-org:cwmp-1-0`, `-1-1`, `-1-2` 세 가지뿐이다. `cwmp-1-3.xsd`(SessionTimeout)와
`cwmp-1-4.xsd`(SupportedCWMPVersions, UseCWMPVersion)는 `cwmp-1-2` 네임스페이스에 헤더 요소만 추가한다.
RPC·구조체 정의는 `cwmp-1-2.xsd`가 기준이다.
