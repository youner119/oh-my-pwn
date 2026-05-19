# knowledge/

OmP agent (VulnHunter / StrategyAgent / Reverser / Exploiter) 가 *모르는 것* 을 채우는 재료 창고.
LLM 단독으로는 닿지 못하는 도메인 지식 — 기법 카탈로그, 과거 CTF writeup, 외부 reference — 을
누적해서 agent 가 file read 로 직접 소비한다.

## 구성

```
knowledge/
├── ctf-pwn/      ← github.com/ljagiello/ctf-skills 의 ctf-pwn/ 카테고리만 vendor
└── writeups/     ← (예정) 사용자가 들고와서 후처리한 과거 CTF 문제별 해설 + exploit
```

다른 카테고리 (ctf-reverse, ctf-misc 등) 의 vendoring 여부는 추후 결정. 필요해지면
`scripts/sync-ctf-pwn.sh` 와 동일한 패턴으로 별도 sync 스크립트를 추가한다.

## ctf-pwn (vendored)

| 항목 | 값 |
|---|---|
| 출처 | <https://github.com/ljagiello/ctf-skills> (디렉토리 `ctf-pwn/`) |
| 라이선스 | MIT (Lukasz Jagiello, 2026) — 원본 `knowledge/ctf-pwn/LICENSE` 그대로 보존 |
| 가져온 날짜 | 2026-05-19 |
| upstream commit | `1af14f9030fee9da46014a8a3ed61a555b81ab98` (`knowledge/ctf-pwn/.upstream` 참조) |
| 가져온 방식 | 수동 vendor (`scripts/sync-ctf-pwn.sh`) |

### 동기화

```bash
# upstream HEAD 로 갱신 (실제 파일 변경)
bash scripts/sync-ctf-pwn.sh

# 무엇이 바뀌는지 미리보기 (실제 변경 없음)
bash scripts/sync-ctf-pwn.sh --dry-run
```

스크립트가 하는 일:
1. `github.com/ljagiello/ctf-skills` 를 임시 디렉토리에 shallow clone.
2. `ctf-pwn/` 하위만 `knowledge/ctf-pwn/` 으로 `rsync -a --delete` (단, `LICENSE` 와
   `.upstream` 은 exclude — 별도로 갱신).
3. upstream LICENSE 를 `knowledge/ctf-pwn/LICENSE` 로 복사.
4. `knowledge/ctf-pwn/.upstream` 에 새 SHA + 날짜 기록.

동기화 후 `git diff knowledge/ctf-pwn/` 로 변경분 확인하고 commit.

### 수정 정책 (중요)

- **`knowledge/ctf-pwn/` 안의 파일을 직접 수정하지 말 것.** sync 시 `--delete` 옵션으로
  upstream 에 없는/다른 내용은 덮어쓰여진다.
- 우리만의 추가 기법, 노트, 본인 writeup 등은 **`knowledge/writeups/`** 또는 `knowledge/` 의
  다른 폴더에 둔다.
- ctf-pwn 자체에 기여하고 싶으면 upstream 에 PR 보낸 뒤 다음 sync 에 반영되도록 한다.

### MIT 라이선스 의무

원본 `LICENSE` 가 `knowledge/ctf-pwn/LICENSE` 에 그대로 보존되므로 *copyright + permission
notice 유지* 의무 충족.

## writeups/ (예정)

사용자가 직접 들고와서 후처리한 과거 CTF 문제 모음. 형식 미정 — 도입할 때 본 README 갱신.

---

## VH/SA prompt 와의 관계 (2026-05-19 시점)

기존 `knowledge/techniques/` (5 technique md + index.md, 구조화 schema) 는 폐기됨. VH/SA prompt
(`src/agents/omp-vulnhunter.ts`, `src/agents/omp-strategist.ts`) 에는 아직 옛 경로
(`knowledge/techniques/index.md`, `knowledge/techniques/stack_bof.md`) 가 hardcode 되어 있어
runtime read 시 깨진다. prompt 를 `knowledge/ctf-pwn/SKILL.md` 기반으로 재작성하는 작업은
별도 task 로 이월.
