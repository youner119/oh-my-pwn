# knowledge/sources/

**Raw original dumps.** 블로그 export, PDF, 외부 기사, writeup 의 challenge binary, 사용자가 외부에서 들고온 비정형 자료.

## 정책

- **Git 추적 X.** 사이즈가 크다 (PDF / binary / 전체 블로그 dump). `.gitignore` 가 `knowledge/sources/*` 전체 ignore. 본 `README.md` 만 whitelist 로 추적.
- **저장 위치는 머신마다 다름.** Repo 밖 별도 디렉토리 / cloud 동기화 폴더 / 외장 등 사용자 결정.
- **공유 금지.** 사용자 본인 private use 만. 외부 발표 / commit / push 금지 (라이선스 제약 무관).

## 어떤 자료를 넣나

| 유형 | 예시 |
|---|---|
| 블로그 export | Project Zero / phrack / 개인 블로그 mhtml/PDF |
| PDF | Whitepaper, conference paper |
| 외부 카탈로그 dump | 정돈 안 된 외부 wiki, link-only repository 의 raw content |
| Writeup 의 challenge binary | `writeups/<ctf>/<chal>/` 의 binary/lib 등 (writeup 본문은 git, blob 은 sources) |
| 임시 자료 | 풀고 있는 챌린지 관련 임시 reference (정리되면 `notes/` 로 derived) |

## Layout (제안)

```
sources/
├── README.md                          ← 본 파일 (only this is tracked)
├── phrack-67-tcache/                  ← 예: phrack 기사 mhtml + PDF
├── glibc-2.39-malloc-internals.pdf    ← 예: 직접 dump
├── kalmarctf-2024-mochi/              ← 예: writeup 의 binary + libc
├── kernel-exploit-dojo/               ← 커널 pwn 도장 (아래 참조)
└── ...
```

각 dump 의 출처 / 라이선스는 *사용자 본인 책임*. 정돈해서 `notes/` 에 derived 만들면 본문에 출처 명시.

## 편입된 대형 dump

### `kernel-exploit-dojo/`

- **출처:** [mito753/Kernel-Exploit-Dojo](https://github.com/mito753/Kernel-Exploit-Dojo) (라이선스 미선언 → **private local use 만**, 외부 공유·재배포 금지).
- **무엇:** Linux 커널 exploitation CTF 100+ 챌린지 아카이브. 버그 클래스 / 기법 / 난이도로 교차 색인. 연도별(`2020`~`2026`) 폴더 + 문제당 `distribution/`(원본) · `exploit/`(익스 코드) · `writeup/`(분석). 루트 `TECHNIQUES.md` = 기법 네비게이션.
- **크기:** ~2.4GB on-disk (대부분 `distribution/` 의 커널 이미지·rootfs 바이너리). `sources/*` gitignore 로 git 밖 — repo·release 용량 무영향.
- **소비 대상:** 현재 OmP 는 kernel CTF 미지원(backlog #1 — pwno-mcp `qemu-system`/`vmlinux` first-class 미구현, agent 는 userland pwn 전용). **kernel 도메인 작업 진입 전까지 dormant.** 그때 agent 가 `writeup/`·`exploit/`·`TECHNIQUES.md` 를 lazy read 로 소비.
- **동기화:** `cd knowledge/sources && git clone --depth 1 https://github.com/mito753/Kernel-Exploit-Dojo.git kernel-exploit-dojo` (머신마다 수동 — vendor sync 스크립트 대상 아님).

## Agent 의 lazy read

Agent prompt 의 lazy add 가이드:
- `notes/` / `writeups/` 의 항목이 `sources/<id>` 를 참조하면 — **있으면 read, 없으면 silently skip**.
- `sources/<id>` 의 존재 자체를 명시적으로 가정하지 않음. 본문 (notes / writeups) 이 self-contained 하도록 작성하는 게 원칙.

자세한 정책은 spec 참조: [`.omc/specs/deep-interview-knowledge-integration.md`](../../.omc/specs/deep-interview-knowledge-integration.md).
