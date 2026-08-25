"""코드 생성·실행 유틸리티

[P2-4] LangGraph-Streamlit/utils.py 에서 이식한 뒤 두 가지를 보강했습니다.

  1. 자기치유 루프(CE3)에서 성공/실패를 구분할 수 있도록 반환 형태 변경
  2. 앱을 공개 배포하므로 LLM 생성 코드를 제한된 네임스페이스에서 실행

2번이 중요합니다. 이 앱은 사용자 질문을 LLM 에 넘겨 pandas/matplotlib 코드를
생성시킨 뒤 실행합니다. 즉 **프롬프트 인젝션이 곧 임의 코드 실행**이 되는 구조라,
공개 URL 에서는 반드시 막아야 합니다.
"""

from __future__ import annotations

import builtins
import contextlib
import io

# 코드 생성 결과가 쓸 수 있는 내장 함수 화이트리스트.
# 데이터 조회·집계·차트에 필요한 것만 남기고 나머지는 전부 차단합니다.
_ALLOWED_BUILTINS = {
    "abs", "all", "any", "bool", "dict", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "int", "isinstance", "issubclass", "len",
    "list", "map", "max", "min", "next", "print", "range", "repr", "reversed",
    "round", "set", "slice", "sorted", "str", "sum", "tuple", "type", "zip",
    "True", "False", "None",
}

# import 를 허용할 모듈. 이 목록 밖은 ImportError 로 거절합니다.
_ALLOWED_MODULES = {
    "pandas", "numpy", "matplotlib", "matplotlib.pyplot", "math", "statistics",
    "datetime", "collections", "itertools", "re",
}

# 소스에 이 문자열이 있으면 실행 전에 거절합니다 (샌드박스 우회 시도 차단).
_FORBIDDEN_TOKENS = (
    # 인터프리터 내부 접근 / 동적 실행
    "__import__", "__builtins__", "__globals__", "__subclasses__", "__class__",
    "__bases__", "__mro__", "__dict__", "eval", "exec", "compile", "open(",
    "input(", "globals(", "locals(", "vars(", "getattr", "setattr", "delattr",
    "breakpoint", "importlib", "marshal", "pickle",
    # 시스템 / 네트워크
    "os.", "sys.", "subprocess", "shutil", "socket", "requests", "urllib",
    "pathlib", "tempfile", "glob",
    # pandas 파일·네트워크 I/O — 이걸 막지 않으면 pd.read_csv('.env') 로
    # 비밀정보가 그대로 유출된다. 실제로 검증하다 발견한 구멍이다.
    "pd.io", "pandas.io",
    "read_csv", "read_json", "read_pickle", "read_parquet", "read_excel",
    "read_table", "read_html", "read_sql", "read_fwf", "read_feather",
    "read_orc", "read_stata", "read_sas", "read_spss", "read_xml",
    "read_gbq", "read_hdf", "read_clipboard",
    "to_csv", "to_json", "to_pickle", "to_parquet", "to_excel", "to_sql",
    "to_hdf", "to_feather", "to_orc", "to_stata", "to_xml", "to_gbq",
    "to_clipboard",
    # numpy 파일 I/O
    "np.save", "np.load", "np.fromfile", "np.tofile", "np.savetxt",
    "np.loadtxt", "np.genfromtxt",
    # 이미지 저장 — 차트 저장은 change_plot_to_save 가 통제해서 붙인다
    "savefig", "imsave", "imread",
)


class SandboxViolation(RuntimeError):
    """생성된 코드가 허용 범위를 벗어났을 때 발생합니다."""


def python_code_parser(text: str) -> str:
    """LLM 응답에서 Python 코드 블록만 추출합니다."""
    processed = text.replace("```python", "```").strip()
    parts = processed.split("```")

    if len(parts) == 1:
        return processed

    return "\n".join(parts[i] for i in range(1, len(parts), 2))


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    root = name.split(".")[0]
    if name not in _ALLOWED_MODULES and root not in _ALLOWED_MODULES:
        raise SandboxViolation(f"허용되지 않은 모듈 import: {name}")
    return builtins.__import__(name, globals, locals, fromlist, level)


def _build_safe_builtins() -> dict:
    safe = {n: getattr(builtins, n) for n in _ALLOWED_BUILTINS if hasattr(builtins, n)}
    safe["__import__"] = _guarded_import
    return safe


def check_code(code: str) -> str | None:
    """실행 전 정적 검사. 문제가 있으면 사유 문자열, 없으면 None."""
    for token in _FORBIDDEN_TOKENS:
        if token in code:
            return f"금지된 표현 사용: {token}"
    return None


def run_code(
    code: str,
    require_output: bool = True,
    pre_checked: bool = False,
    **namespace,
) -> tuple[str, bool]:
    """코드를 제한된 네임스페이스에서 실행하고 (stdout, 성공여부) 를 돌려줍니다.

    require_output:
        조회 코드(pandas)는 print() 출력이 없으면 실패로 봐야 하지만,
        차트 코드(matplotlib)는 원래 stdout 이 비어 있는 것이 정상입니다.
        호출부가 어느 쪽인지 알려주도록 분리했습니다.

    pre_checked:
        차트 경로는 LLM 코드를 먼저 check_code 로 검사한 뒤 우리가 통제하는
        savefig 구문을 덧붙입니다. 그 뒤 다시 검사하면 우리가 붙인 savefig 가
        걸리므로, 이미 검사했음을 알려 정적 검사를 건너뜁니다.
        (제한된 builtins 로 실행하는 런타임 방어는 그대로 적용됩니다)
    """
    if not pre_checked:
        violation = check_code(code)
        if violation:
            return f"SandboxViolation: {violation}", False

    scope = dict(namespace)
    scope["__builtins__"] = _build_safe_builtins()

    buffer = io.StringIO()
    ok = True
    try:
        with contextlib.redirect_stdout(buffer):
            exec(code, scope)  # noqa: S102 - 화이트리스트 네임스페이스에서만 실행
    except Exception as exc:
        ok = False
        print(f"{type(exc).__name__}: {exc}", file=buffer)

    output = buffer.getvalue().strip()
    if ok and require_output and not output:
        output = "(출력 없음 — print() 로 결과를 찍어야 합니다)"
        ok = False
    return output, ok


def change_plot_to_save(code: str, path: str = "plot.png") -> str:
    """matplotlib 코드의 plt.show() 를 우리가 지정한 경로로의 저장으로 바꿉니다.

    저장 경로를 LLM 이 정하게 두면 임의 경로 파일 쓰기가 되므로,
    savefig 는 check_code 에서 차단하고 이 함수만 붙일 수 있게 했습니다.
    """
    code = code.replace("plt.show()", "")
    return code + f"\nplt.savefig(r'{path}', bbox_inches='tight', dpi=120)\nplt.close()"
