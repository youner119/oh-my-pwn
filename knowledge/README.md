# knowledge/

OmP agent (VulnHunter / StrategyAgent / Reverser / Exploiter) 가 *모르는 것* 을 채우는 재료 창고.
LLM 단독으로는 닿지 못하는 도메인 지식 — 기법 카탈로그, 원자료 dump, 과거 CTF writeup, agent 누적 인사이트 — 을 누적해서 agent 가 file read 로 직접 소비한다.

Spec: [`.omc/specs/deep-interview-knowledge-integration.md`](../.omc/specs/deep-interview-knowledge-integration.md)

## 4 영역 구조

```
knowledge/
├── README.md          ← 본 파일
├── ctf-pwn/           ← Vendor: 정돈된 기법 카탈로그 (MIT). git 안 (~500K).
├── ctf-reverse/       ← Vendor: Reverser 용 카탈로그 (MIT). git 안 (~430K).
├── how2heap/          ← (계획) Vendor: heap 기법 C source + README.
├── sources/           ← Raw original dumps. **git 밖** (사이즈 큼).
├── notes/             ← Agent-curated wiki. 빈 채로 시작, 자라남.
└── writeups/          ← User-owned CTF case records. git 안.
```

### 영역별 정책

| 영역 | Write | Read | Git 추적 | 비고 |
|---|---|---|---|---|
| `<vendor>/` (top-level) | sync 스크립트만 | 모든 agent | ✅ | 정돈된 외부 카탈로그. Touch 금지 — sync 시 덮어씀. |
| `sources/` | 사용자 (수동 dump) | 모든 agent (있을 때) | ❌ gitignore | 블로그/PDF/writeup binary 등 raw. Repo 밖에 저장 (cloud/외장/별도 dir). 사이즈 큼. |
| `notes/` | agent + 사용자 | 모든 agent | ✅ | challenge 풀다가 발견한 generic 인사이트. frontmatter 권장. |
| `writeups/` | 사용자 | 모든 agent | ✅ | `<ctf>/<chal>/{writeup.md, exploit.py, tags.yaml}`. Binary/large blob 는 `sources/` 로 분리. |

### Graceful skip

`notes/` / `writeups/` 가 `sources/<id>` 를 참조해도 **부재 시 silently skip**. sources 는 머신마다 있을 수도 없을 수도 있는 "보조 자료" — 본문은 self-contained 하게 작성.

## Vendor 목록

| Vendor | 주 소비자 | 출처 | sync 스크립트 |
|---|---|---|---|
| `ctf-pwn/` | VulnHunter / StrategyAgent / Exploiter | [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) — `ctf-pwn/` 카테고리, MIT | `scripts/sync-ctf-pwn.sh` |
| `ctf-reverse/` | Reverser (anti-debug, custom VM, obfuscation, language-specific 패턴) | 동상 — `ctf-reverse/` 카테고리, MIT | `scripts/sync-ctf-reverse.sh` |
| `how2heap/` | VulnHunter / StrategyAgent / Exploiter (heap 도메인) | [shellphish/how2heap](https://github.com/shellphish/how2heap), MIT (branch: master) | `scripts/sync-how2heap.sh` |

### 메타데이터 (각 vendor 폴더)

- 원본 `LICENSE` 보존
- `.upstream` 파일 — repo URL, commit SHA, sync 날짜

## 동기화

```bash
# upstream HEAD 로 갱신
bash scripts/sync-ctf-pwn.sh
bash scripts/sync-ctf-reverse.sh
bash scripts/sync-how2heap.sh

# 무엇이 바뀌는지 미리보기 (실제 변경 없음)
bash scripts/sync-ctf-pwn.sh --dry-run
```

위 스크립트들은 모두 `scripts/sync-vendored.sh <vendor>` 의 thin wrapper —
직접 `bash scripts/sync-vendored.sh how2heap` 형태로도 호출 가능.

각 스크립트가 하는 일:
1. upstream repo 를 임시 디렉토리에 shallow clone (vendor-specific branch — 대부분 `main`, how2heap 만 `master`)
2. 해당 subpath 만 `knowledge/<vendor>/` 으로 `rsync -a --delete` (단 `.upstream`, `LICENSE`, `.git` 은 exclude). Subpath 가 빈 문자열이면 repo root 전체.
3. upstream `LICENSE` 복사 (부재 시 warning 후 계속)
4. `.upstream` 에 새 SHA + 날짜 기록

동기화 후 `git diff knowledge/<vendor>/` 로 변경분 확인하고 commit.

## 수정 정책

- **Vendor 폴더 안의 파일 직접 수정 금지** — sync 시 `--delete` 로 덮어쓰여짐. 추가 인사이트는 `notes/` 또는 `writeups/`.
- **`sources/` 는 사용자 본인 dump 만** — repo 안에 commit 안 함 (gitignore). 외부 공유 금지 (라이선스 무관 private use).
- **`notes/` / `writeups/` 는 사용자 + agent 자유** — agent 가 challenge 풀다가 발견하면 정해진 INDEX 패턴 따라 in-line 추가.

## MIT 라이선스 의무 (vendor)

원본 `LICENSE` 가 각 vendor 폴더에 보존되므로 *copyright + permission notice 유지* 의무 충족.

## Agent prompt 와의 관계

VH/SA/Exploiter/Reverser prompt 가 default base 로 vendor SKILL.md 를 lazy read, domain trigger 시 추가 vendor (how2heap 등) lazy add. 자세한 path 매핑은 spec 의 "Per-agent reference 모델" 섹션 참조.

옛 `knowledge/techniques/index.md` hardcode 가 일부 prompt 에 남아있다 — K1-K4 task 에서 새 path (`knowledge/ctf-pwn/SKILL.md` 등) 로 정정 예정.
