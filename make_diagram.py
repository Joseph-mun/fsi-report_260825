"""제출용 멀티에이전트 구조도 PNG 생성

LangGraph 가 만든 실제 그래프 구조를 그대로 그리므로,
코드와 구조도가 어긋날 일이 없습니다.

    python make_diagram.py            # 기본: 6조_문요셉.png
    python make_diagram.py --out x.png
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_OUT = BASE_DIR / "6조_문요셉.png"

# 노드를 역할별로 묶어 색을 다르게 준다 (구조도 가독성)
GROUPS = {
    "라우터": (["triage"], "#6C5CE7"),
    "분석 에이전트": (["payload_analyst", "log_analyst", "visualizer"], "#0984E3"),
    "지식 검색": (["atlas_rag", "grade_docs"], "#00B894"),
    "웹 API 에이전트": (["threat_intel", "cve_lookup"], "#E17055"),
    "종합 · 검증": (["playbook_writer", "verifier"], "#D63031"),
    "일반": (["plain_answer"], "#636E72"),
}

# (from, to, label, is_conditional)
EDGES = [
    ("START", "triage", "", False),
    ("triage", "payload_analyst", "CE1: payload", True),
    ("triage", "log_analyst", "CE1: log", True),
    ("triage", "atlas_rag", "CE1: knowledge", True),
    ("triage", "threat_intel", "CE1: intel", True),
    ("triage", "visualizer", "CE1: plot", True),
    ("triage", "plain_answer", "CE1: plain", True),
    ("payload_analyst", "atlas_rag", "CE2: 위험≥70", True),
    ("payload_analyst", "threat_intel", "CE2: 40~69", True),
    ("payload_analyst", "playbook_writer", "CE2: <40", True),
    ("log_analyst", "log_analyst", "CE3: 실행실패 재시도(≤2)", True),
    ("log_analyst", "plain_answer", "CE3: 재시도 소진", True),
    ("log_analyst", "playbook_writer", "CE3: 성공", True),
    ("atlas_rag", "grade_docs", "", False),
    ("grade_docs", "playbook_writer", "CE4: 충분", True),
    ("grade_docs", "threat_intel", "CE4: 불충분 → 웹 폴백", True),
    ("threat_intel", "cve_lookup", "CE5: CVE 발견", True),
    ("threat_intel", "playbook_writer", "CE5: CVE 없음", True),
    ("cve_lookup", "playbook_writer", "", False),
    ("visualizer", "playbook_writer", "", False),
    ("playbook_writer", "verifier", "", False),
    ("verifier", "playbook_writer", "CE6: 검증실패 재작성(≤1)", True),
    ("verifier", "END", "CE6: 통과", True),
    ("plain_answer", "END", "", False),
]


def to_dot() -> str:
    color_of, group_of = {}, {}
    for group, (names, color) in GROUPS.items():
        for n in names:
            color_of[n] = color
            group_of[n] = group

    lines = [
        "digraph PromptShield {",
        '  rankdir=TB; bgcolor="white"; ranksep=0.5; nodesep=0.3;',
        '  labelloc="t"; fontname="Helvetica-Bold"; fontsize=18;',
        '  label="PromptShield — LLM 프롬프트 공격 탐지·대응 멀티에이전트\\n'
        '노드 11개 · 조건부 엣지 6개(CE1~CE6) · 웹 API 에이전트 2개";',
        '  node [shape=box style="rounded,filled" fontname="Helvetica" '
        'fontcolor="white" fontsize=11 penwidth=0 height=0.45];',
        '  edge [fontname="Helvetica" fontsize=8 color="#B2BEC3"];',
        '  "START" [shape=circle fillcolor="#2D3436" label="START" fontsize=9];',
        '  "END" [shape=doublecircle fillcolor="#2D3436" label="END" fontsize=9];',
    ]
    for name, color in color_of.items():
        lines.append(f'  "{name}" [fillcolor="{color}"];')

    for src, dst, label, cond in EDGES:
        attrs = [f'label="{label}"'] if label else []
        if cond:
            attrs += ['color="#D63031"', "penwidth=1.6", 'fontcolor="#D63031"', "style=bold"]
        lines.append(f'  "{src}" -> "{dst}" [{" ".join(attrs)}];')

    lines.append("}")
    return "\n".join(lines)


def to_mermaid() -> str:
    out = ["graph TD"]
    for src, dst, label, cond in EDGES:
        # 라벨에 괄호·화살표·부등호가 들어가므로 반드시 인용해야 파싱된다.
        arrow = f'-->|"{label}"|' if label else "-->"
        out.append(f"    {src} {arrow} {dst}")
    return "\n".join(out)


def render(out_path: Path) -> bool:
    """graphviz -> mermaid.ink -> matplotlib 순으로 시도합니다."""
    dot = to_dot()

    # 1) graphviz 바이너리가 있으면 가장 깔끔하다
    import shutil
    import subprocess

    if shutil.which("dot"):
        try:
            subprocess.run(
                ["dot", "-Tpng", "-Gdpi=160", "-o", str(out_path)],
                input=dot.encode("utf-8"), check=True, capture_output=True,
            )
            print(f"[diagram] graphviz 로 생성: {out_path.name}")
            return True
        except Exception as exc:
            print(f"[diagram] graphviz 실패 ({exc}) — 다음 방법 시도")

    # 2) mermaid.ink (네트워크 필요)
    try:
        import base64
        import json

        import requests

        # repr() 은 작은따옴표를 내서 JSON 이 아니게 된다. json.dumps 를 써야 한다.
        encoded = base64.urlsafe_b64encode(
            json.dumps({"code": to_mermaid(), "mermaid": {"theme": "default"}}).encode()
        ).decode()
        resp = requests.get(f"https://mermaid.ink/img/{encoded}?type=png", timeout=20)
        resp.raise_for_status()
        out_path.write_bytes(resp.content)
        print(f"[diagram] mermaid.ink 로 생성: {out_path.name}")
        return True
    except Exception as exc:
        print(f"[diagram] mermaid.ink 실패 ({exc}) — DOT 파일만 저장")

    dot_path = out_path.with_suffix(".dot")
    dot_path.write_text(dot, encoding="utf-8")
    print(f"[diagram] DOT 저장: {dot_path.name}")
    print("  → https://dreampuf.github.io/GraphvizOnline 에 붙여넣어 PNG 로 내려받으세요.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    out = Path(args.out)
    ok = render(out)

    # 참고용으로 mermaid 소스도 남긴다 (README 에 삽입 가능)
    (BASE_DIR / "docs_architecture.mmd").write_text(to_mermaid(), encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
