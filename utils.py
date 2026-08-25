"""코드 생성·실행 유틸리티

[P2-4] LangGraph-Streamlit/utils.py 에서 이식한 뒤,
자기치유 루프에서 성공/실패를 구분할 수 있도록 반환 형태를 바꿨습니다.
"""

from __future__ import annotations

import contextlib
import io


def python_code_parser(text: str) -> str:
    """LLM 응답에서 Python 코드 블록만 추출합니다."""
    processed = text.replace("```python", "```").strip()
    parts = processed.split("```")

    if len(parts) == 1:
        return processed

    return "\n".join(parts[i] for i in range(1, len(parts), 2))


def run_code(code: str, require_output: bool = True, **namespace) -> tuple[str, bool]:
    """코드를 실행하고 (stdout, 성공여부) 를 돌려줍니다.

    원본은 문자열만 반환해 호출부가 "Error" 라는 문자열을 검사해야 했습니다.
    조회 결과 자체에 'Error' 라는 단어가 들어있으면 오탐이 나므로,
    예외 발생 여부를 별도 불리언으로 분리했습니다.

    require_output:
        조회 코드(pandas)는 print() 출력이 없으면 실패로 봐야 하지만,
        차트 코드(matplotlib)는 원래 stdout 이 비어 있는 것이 정상입니다.
        호출부가 어느 쪽인지 알려주도록 분리했습니다.
    """
    buffer = io.StringIO()
    ok = True
    try:
        with contextlib.redirect_stdout(buffer):
            exec(code, namespace)  # noqa: S102 - 실습 목적의 의도된 동적 실행
    except Exception as exc:
        ok = False
        print(f"{type(exc).__name__}: {exc}", file=buffer)

    output = buffer.getvalue().strip()
    if ok and require_output and not output:
        output = "(출력 없음 — print() 로 결과를 찍어야 합니다)"
        ok = False
    return output, ok


def change_plot_to_save(code: str, path: str = "plot.png") -> str:
    """matplotlib 코드의 plt.show() 를 파일 저장으로 바꿉니다."""
    if "plt.savefig" in code:
        return code
    code = code.replace("plt.show()", "")
    return code + f"\nplt.savefig('{path}', bbox_inches='tight', dpi=120)\nplt.close()"
