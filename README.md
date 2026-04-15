# oh-my-pwn (OmP)

> CTF pwnable 자동 솔버 multi-agent harness — **독립 opencode 플러그인**

바이너리와 Dockerfile 한 쌍만 있으면 Load → EnvSetup → Reverse → VulnHunt
→ Exploit → Verify 파이프라인을 agent들이 순차적으로 돌립니다. 사람은
언제든 prompt 채널로 개입해서 교정 가능.

**상태:** MVP 개발 중 (M2 Reverser 단계, T08 user test gate).

## 빠른 시작

```bash
# 1. 세팅 (현재 머신에서 처음 쓸 때 / repo 경로 이동 시)
./scripts/setup-omp.sh

# 2. 새 shell
exec zsh

# 3. Ghidra GUI 실행 + "omp"라는 이름의 project 생성/열기 + MCP server 시작

# 4. OmP 전용 opencode TUI 시작
omp
```

## 문서

전반적 이해는 **[docs/README.md](docs/README.md)** 부터 읽으시면 됩니다.
세부는:

- [docs/architecture.md](docs/architecture.md) — opencode 플러그인 구조, config/tool hook, 빌드/배포
- [docs/agents.md](docs/agents.md) — agent 설계, factory 패턴, 프롬프트 구성 원칙
- [docs/state-and-io.md](docs/state-and-io.md) — `.omp/` 레이아웃, 상태 관리, human intervention
- [docs/tools.md](docs/tools.md) — `omp_*` tool 7개
- [docs/templates.md](docs/templates.md) — 재사용 가능 템플릿 시스템
- [docs/development.md](docs/development.md) — 개발 환경 / 빌드 / 테스트 workflow

## 프로젝트 spec

- `.omc/specs/deep-interview-oh-my-pwn.md` — 원본 요구사항 spec (T00–T24)
- `.omc/specs/deep-interview-reverser-redesign.md` — Reverser agent 재설계
- `.omc/state/current-task.md` — 현재 진행 상황 (세션 연속성)

## 라이선스

Private / personal use. 배포 예정 없음.
