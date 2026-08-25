"""조건부 엣지 분기 함수 단위 테스트 (LLM 호출 없음)

    python -m tests.test_routes
"""

from promptshield.graph import (
    route_after_code, route_after_grade, route_after_intel,
    route_after_verify, route_by_risk, route_triage,
)

CASES = [
    ("CE1 정상 라우팅",   route_triage,       {"route": "log"},                       "log"),
    ("CE1 미지정 폴백",   route_triage,       {},                                     "plain"),
    ("CE2 고위험",        route_by_risk,      {"risk": {"score": 85}},                "deep"),
    ("CE2 경계값 70",     route_by_risk,      {"risk": {"score": 70}},                "deep"),
    ("CE2 중위험",        route_by_risk,      {"risk": {"score": 55}},                "intel"),
    ("CE2 경계값 40",     route_by_risk,      {"risk": {"score": 40}},                "intel"),
    ("CE2 저위험",        route_by_risk,      {"risk": {"score": 39}},                "direct"),
    ("CE2 risk 없음",     route_by_risk,      {},                                     "direct"),
    ("CE3 실행 성공",     route_after_code,   {"code_ok": True, "code_retry": 1},     "ok"),
    ("CE3 실패 재시도",   route_after_code,   {"code_ok": False, "code_retry": 1},    "retry"),
    ("CE3 재시도 소진",   route_after_code,   {"code_ok": False, "code_retry": 2},    "giveup"),
    # 아래 두 건은 예전에 출력 문자열로 성패를 추측하던 시절의 오판 케이스다.
    ("CE3 미등록 예외",   route_after_code,   {"code_ok": False, "code_retry": 0, "data": "ZeroDivisionError: division by zero"}, "retry"),
    ("CE3 오류처럼 보이는 정상출력", route_after_code, {"code_ok": True, "code_retry": 0, "data": "ValueError 관련 요청 0건"}, "ok"),
    ("CE4 검색 충분",     route_after_grade,  {"grade": "sufficient"},                "ok"),
    ("CE4 검색 불충분",   route_after_grade,  {"grade": "insufficient"},              "fallback"),
    ("CE4 grade 없음",    route_after_grade,  {},                                     "ok"),
    ("CE4 verdict 오염 무시", route_after_grade, {"verdict": "insufficient"},         "ok"),
    ("CE5 CVE 발견",      route_after_intel,  {"web_results": "see CVE-2024-5184"},   "cve"),
    ("CE5 CVE 없음",      route_after_intel,  {"web_results": "no identifiers"},      "done"),
    ("CE6 검증 통과",     route_after_verify, {"verdict": "pass"},                    "pass"),
    ("CE6 실패 재작성",   route_after_verify, {"verdict": "fail", "rewrite_count": 1}, "rewrite"),
    ("CE6 재작성 소진",   route_after_verify, {"verdict": "fail", "rewrite_count": 2}, "giveup"),
]


def main() -> int:
    failures = 0
    for name, fn, state, expected in CASES:
        got = fn(state)
        ok = got == expected
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name:16} -> {got!r} (기대 {expected!r})")

    print(f"\n{len(CASES) - failures}/{len(CASES)} 통과")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
