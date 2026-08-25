"""그래프 State 정의와 라우팅 상수"""

from __future__ import annotations

from typing import TypedDict


class State(TypedDict, total=False):
    """PromptShield 그래프의 공유 상태.

    중요: 각 노드는 **자기가 바꾼 키만** 담아 반환합니다.
    LangGraph 는 부분 dict 를 병합하므로, 전체 dict 를 반환하면
    앞 노드가 계산해 둔 risk / citations 가 덮여 사라집니다.
    """

    question: str        # 사용자 질문
    route: str           # triage 판정 결과
    generation: str      # 최종 답변
    code: str            # 생성된 pandas / matplotlib 코드
    data: str            # 코드 실행 결과
    plot: str            # 생성된 차트 이미지 경로 (없으면 빈 문자열)
    context: str         # RAG 로 검색한 원문
    web_results: str     # Tavily / NVD 결과
    risk: dict           # {score, level, technique, rationale}
    citations: list      # 근거 출처 목록
    code_retry: int      # 자기치유 루프 카운터 (상한 MAX_CODE_RETRY)
    rewrite_count: int   # 재작성 루프 카운터 (상한 MAX_REWRITE)
    verdict: str         # 검증 결과 pass / fail
    notes: list          # 사용자에게 보여줄 진행 메모


# 루프 상한 — 모든 경로가 유한 단계 안에 END 에 도달하도록 보장합니다.
MAX_CODE_RETRY = 2
MAX_REWRITE = 1

# triage 가 낼 수 있는 값. 화이트리스트 밖의 값은 plain 으로 떨어뜨립니다.
ROUTES = {
    "payload": "payload_analyst",
    "log": "log_analyst",
    "knowledge": "atlas_rag",
    "intel": "threat_intel",
    "plot": "visualizer",
    "plain": "plain_answer",
}

# 위험 점수 구간
RISK_HIGH = 70
RISK_MEDIUM = 40


def risk_level(score: int) -> str:
    if score >= RISK_HIGH:
        return "HIGH"
    if score >= RISK_MEDIUM:
        return "MEDIUM"
    return "LOW"
