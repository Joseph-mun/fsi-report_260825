"""StateGraph 조립

조건부 엣지 6곳(CE1~CE6)이 이 파일의 핵심입니다.
각 분기 함수는 순수 함수로 두어 그래프 없이도 단위 테스트할 수 있게 했습니다.
"""

from __future__ import annotations

from pathlib import Path

from langgraph.graph import END, StateGraph

from .nodes import PromptShield
from .schema import MAX_CODE_RETRY, MAX_REWRITE, RISK_HIGH, RISK_MEDIUM, ROUTES, State

# ---------------------------------------------------------------------------
# 분기 함수 (조건부 엣지에서 호출)
# ---------------------------------------------------------------------------


def route_triage(state: State) -> str:
    """CE1 — 질문 유형에 따라 6개 전문 노드로 분배."""
    return state.get("route", "plain")


def route_by_risk(state: State) -> str:
    """CE2 — 위험 등급이 높을수록 더 깊은 근거 수집을 강제한다.

    고위험 판정을 근거 없이 통보하면 오탐일 때 대응 비용이 크므로,
    HIGH 는 지식베이스 확인을, MEDIUM 은 최신 사례 확인을 반드시 거치게 한다.
    """
    score = int((state.get("risk") or {}).get("score", 0))
    if score >= RISK_HIGH:
        return "deep"
    if score >= RISK_MEDIUM:
        return "intel"
    return "direct"


def route_after_code(state: State) -> str:
    """CE3 — 코드 실행 자기치유 루프.

    LLM 이 만든 pandas 코드는 열 이름 오타나 dtype 착오로 자주 실패한다.
    오류 메시지를 되먹여 재생성시키되, MAX_CODE_RETRY 로 상한을 건다.
    """
    # log_analyst 가 넘겨준 실행 성패를 그대로 신뢰한다.
    # 출력 문자열을 다시 파싱하면 목록에 없는 예외(ZeroDivisionError 등)를
    # 성공으로, 'ValueError' 로 시작하는 정상 출력을 실패로 오판한다.
    if state.get("code_ok", True):
        return "ok"
    if int(state.get("code_retry") or 0) < MAX_CODE_RETRY:
        return "retry"
    return "giveup"


def route_after_grade(state: State) -> str:
    """CE4 — CRAG. 검색이 빈약하면 웹 인텔로 보강한다."""
    return "fallback" if state.get("grade") == "insufficient" else "ok"


def route_after_intel(state: State) -> str:
    """CE5 — 웹 결과에 CVE 가 언급되면 NVD 로 정확한 수치를 확인한다."""
    from .tools import find_cve_ids

    haystack = f"{state.get('web_results','')}\n{state.get('question','')}"
    return "cve" if find_cve_ids(haystack) else "done"


def route_after_verify(state: State) -> str:
    """CE6 — 근거 검증 실패 시 1회에 한해 재작성시킨다."""
    if state.get("verdict") == "pass":
        return "pass"
    if int(state.get("rewrite_count") or 0) <= MAX_REWRITE:
        return "rewrite"
    return "giveup"


# ---------------------------------------------------------------------------
# 그래프 조립
# ---------------------------------------------------------------------------

NODE_NAMES = [
    "triage", "payload_analyst", "log_analyst", "atlas_rag", "grade_docs",
    "threat_intel", "cve_lookup", "visualizer", "playbook_writer",
    "verifier", "plain_answer",
]


def build_graph(shield: PromptShield):
    graph = StateGraph(State)

    for name in NODE_NAMES:
        graph.add_node(name, getattr(shield, name))

    graph.set_entry_point("triage")

    # --- CE1: 질문 유형 분배 (6-way) ---------------------------------------
    graph.add_conditional_edges("triage", route_triage, dict(ROUTES))

    # --- CE2: 위험 등급별 조사 깊이 ----------------------------------------
    graph.add_conditional_edges("payload_analyst", route_by_risk, {
        "deep": "atlas_rag",
        "intel": "threat_intel",
        "direct": "playbook_writer",
    })

    # --- CE3: 코드 실행 자기치유 루프 --------------------------------------
    graph.add_conditional_edges("log_analyst", route_after_code, {
        "retry": "log_analyst",
        "giveup": "plain_answer",
        "ok": "playbook_writer",
    })

    # --- CE4: CRAG 검색 품질 채점 ------------------------------------------
    graph.add_conditional_edges("grade_docs", route_after_grade, {
        "ok": "playbook_writer",
        "fallback": "threat_intel",
    })

    # --- CE5: CVE 발견 시 NVD 조회 -----------------------------------------
    graph.add_conditional_edges("threat_intel", route_after_intel, {
        "cve": "cve_lookup",
        "done": "playbook_writer",
    })

    # --- CE6: 근거 검증 후 재작성 여부 -------------------------------------
    graph.add_conditional_edges("verifier", route_after_verify, {
        "pass": END,
        "rewrite": "playbook_writer",
        "giveup": END,
    })

    # --- 고정 엣지 ---------------------------------------------------------
    graph.add_edge("atlas_rag", "grade_docs")
    graph.add_edge("cve_lookup", "playbook_writer")
    graph.add_edge("visualizer", "playbook_writer")
    graph.add_edge("playbook_writer", "verifier")
    graph.add_edge("plain_answer", END)

    return graph.compile()


def create_app(
    openai_api_key: str,
    tavily_api_key: str | None,
    data_dir: Path,
    plot_dir: Path,
):
    """PromptShield 리소스를 준비하고 컴파일된 그래프를 돌려줍니다."""
    shield = PromptShield(openai_api_key, tavily_api_key, data_dir, plot_dir)
    return shield, build_graph(shield)
