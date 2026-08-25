"""그래프 구조가 과제 요건을 만족하는지 검증 (LLM 호출 없음)

    python -m tests.test_graph
"""

from langgraph.graph import END, StateGraph

from promptshield.graph import NODE_NAMES, build_graph
from promptshield.schema import State

MIN_CONDITIONAL_EDGES = 5
MIN_NODES = 5


class _Stub:
    """노드 함수 자리만 채우는 더미 (구조만 검사하므로 실행하지 않음)."""

    def __getattr__(self, name):
        return lambda state: {}


def main() -> int:
    app = build_graph(_Stub())
    g = app.get_graph()

    nodes = [n for n in g.nodes if not n.startswith("__")]
    cond_sources = sorted({e.source for e in g.edges if getattr(e, "conditional", False)})
    cond_branches = sum(1 for e in g.edges if getattr(e, "conditional", False))

    print(f"노드            : {len(nodes)}개 {sorted(nodes)}")
    print(f"조건부 엣지     : {len(cond_sources)}곳 {cond_sources}")
    print(f"조건부 분기 총합: {cond_branches}개")
    print(f"전체 엣지       : {len(g.edges)}개")

    checks = [
        (f"노드 {MIN_NODES}개 이상", len(nodes) >= MIN_NODES),
        (f"조건부 엣지 {MIN_CONDITIONAL_EDGES}개 이상", len(cond_sources) >= MIN_CONDITIONAL_EDGES),
        ("선언한 노드가 모두 그래프에 존재", set(NODE_NAMES) == set(nodes)),
        ("END 로 가는 경로 존재", any(e.target == "__end__" for e in g.edges)),
    ]

    print()
    failures = 0
    for label, ok in checks:
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
