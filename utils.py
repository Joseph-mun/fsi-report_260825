"""코드 생성·실행 유틸리티

이 앱은 사용자 질문을 LLM 에 넘겨 pandas/matplotlib 코드를 만든 뒤 실행합니다.
공개 URL 로 배포하므로 **프롬프트 인젝션이 곧 임의 코드 실행**이 되지 않도록
막아야 합니다.

## 왜 AST 검사인가

처음에는 금지 문자열 목록(블록리스트)으로 막았는데, 실제로 뚫렸습니다.

    o = pd._libs.pandas.compat.os      # 소스에 'os.' 라는 문자열이 없다
    o.system('...')                    # 그래도 진짜 os 모듈이다

`pd` 라는 살아있는 모듈 객체가 스코프에 있는 한, 점 표기법을 따라가면
어떤 표준 모듈이든 닿습니다. 소스 문자열만 훑는 방식으로는 이 경로를 셀 수 없습니다.

그래서 **구조**를 검사합니다. 파이썬에서 내부 구현으로 내려가는 길은 거의 전부
밑줄로 시작하는 이름(`_libs`, `__class__`, `__globals__`)을 거치므로,
밑줄로 시작하는 이름·속성 접근을 전부 거부하면 그 통로가 통째로 닫힙니다.

## 3중 방어

1. AST 구조 검사 — 밑줄 이름, 위험 속성명, 미허용 import, while/class 거부
2. 런타임 제한   — 화이트리스트 내장함수 + import 후크
3. 실행 시간 상한 — 15초 초과 시 중단 (무한 루프 방어)
"""

from __future__ import annotations

import ast
import builtins
import contextlib
import io
import threading

# 코드가 쓸 수 있는 내장 함수. 데이터 조회·집계·차트에 필요한 것만 남깁니다.
_ALLOWED_BUILTINS = {
    "abs", "all", "any", "bool", "dict", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "int", "isinstance", "issubclass", "len",
    "list", "map", "max", "min", "next", "print", "range", "repr", "reversed",
    "round", "set", "slice", "sorted", "str", "sum", "tuple", "type", "zip",
    "True", "False", "None",
}

# import 를 허용할 모듈. 이 목록 밖은 거부합니다.
_ALLOWED_MODULES = {
    "pandas", "numpy", "matplotlib", "matplotlib.pyplot", "math", "statistics",
    "datetime", "collections", "itertools", "re",
}

# 속성 접근으로 닿으면 안 되는 이름. 밑줄 규칙과 겹치지만,
# `pd.compat.os` 처럼 밑줄 없이 노출되는 경로를 함께 막습니다.
_FORBIDDEN_ATTRS = {
    # 모듈로 가는 통로
    "os", "sys", "subprocess", "socket", "shutil", "pathlib", "tempfile",
    "importlib", "pickle", "marshal", "ctypes", "platform", "builtins",
    "compat", "io", "requests", "urllib", "http", "glob", "inspect",
    "threading", "multiprocessing", "signal", "gc", "code", "codeop",
    # 실행·반영
    "system", "popen", "spawn", "fork", "exec", "eval", "compile",
    "environ", "getenv", "putenv",
    "getattr", "setattr", "delattr", "vars", "globals", "locals",
    # 파일 I/O (pandas/numpy/matplotlib)
    "read_csv", "read_json", "read_pickle", "read_parquet", "read_excel",
    "read_table", "read_html", "read_sql", "read_fwf", "read_feather",
    "read_orc", "read_stata", "read_sas", "read_spss", "read_xml",
    "read_gbq", "read_hdf", "read_clipboard",
    "to_csv", "to_json", "to_pickle", "to_parquet", "to_excel", "to_sql",
    "to_hdf", "to_feather", "to_orc", "to_stata", "to_xml", "to_gbq",
    "to_clipboard", "to_string", "to_html", "to_latex", "to_markdown",
    "save", "load", "fromfile", "tofile", "savetxt", "loadtxt", "genfromtxt",
    "savez", "savez_compressed", "memmap",
    # 이미지 저장 — 차트 저장은 change_plot_to_save 가 통제해서 붙인다
    "savefig", "imsave", "imread", "imshow_file",
    # 표현식 평가기
    "query", "eval",
    # 포맷 문자열 — '{0.__class__.__bases__}'.format(x) 처럼 속성 접근이
    # 문자열 리터럴 안에 숨어 AST 검사를 통과한다. f-string 은 구문 트리에
    # 그대로 드러나므로 검사에 걸리지만, .format() 은 보이지 않는다.
    "format", "format_map",
    # 스타일러(파일 출력 경로를 가진다)
    "style",
}

# 이름(변수/함수)으로 직접 부르면 안 되는 것. 내장함수 화이트리스트로도 막히지만
# 오류 메시지를 명확히 하려고 별도로 검사합니다.
_FORBIDDEN_NAMES = {
    "eval", "exec", "compile", "open", "input", "breakpoint",
    "getattr", "setattr", "delattr", "globals", "locals", "vars", "dir",
    "__import__", "memoryview", "bytearray",
}


class SandboxViolation(RuntimeError):
    """생성된 코드가 허용 범위를 벗어났을 때 발생합니다."""


def python_code_parser(text: str) -> str:
    """LLM 응답에서 Python 코드 블록만 추출합니다."""
    processed = text.replace("```python", "```").strip()
    parts = processed.split("```")

    if len(parts) == 1:
        return processed

    return "\n".join(parts[i] for i in range(1, len(parts), 2))


def check_code(code: str) -> str | None:
    """실행 전 구조 검사. 문제가 있으면 사유 문자열, 없으면 None."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"구문 오류: {exc.msg} (line {exc.lineno})"

    for node in ast.walk(tree):
        # 1) 밑줄로 시작하는 속성 접근 — 내부 구현으로 내려가는 통로를 막는다.
        #    pd._libs.pandas.compat.os 같은 경로가 여기서 걸린다.
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                return f"내부 속성 접근 금지: .{node.attr}"
            if node.attr in _FORBIDDEN_ATTRS:
                return f"허용되지 않은 속성 접근: .{node.attr}"

        # 2) 밑줄로 시작하는 이름 (__builtins__, __import__ 등)
        if isinstance(node, ast.Name):
            if node.id.startswith("_"):
                return f"내부 이름 사용 금지: {node.id}"
            if node.id in _FORBIDDEN_NAMES:
                return f"허용되지 않은 함수 사용: {node.id}"

        # 3) import 는 허용 목록만
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if alias.name not in _ALLOWED_MODULES and root not in _ALLOWED_MODULES:
                    return f"허용되지 않은 모듈 import: {alias.name}"
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".")[0]
            if module not in _ALLOWED_MODULES and root not in _ALLOWED_MODULES:
                return f"허용되지 않은 모듈 import: {module}"

        # 4) while 루프 금지 — 데이터 조회·차트에 필요 없고, 무한 루프로
        #    공개 앱을 멈춰 세우는 가장 쉬운 수단이다.
        if isinstance(node, ast.While):
            return "while 루프는 허용되지 않습니다 (pandas 연산을 사용하세요)"

        # 5) 클래스 정의 금지 — 메서드 해석 순서를 타고 내려가는 우회의 출발점
        if isinstance(node, ast.ClassDef):
            return "class 정의는 허용되지 않습니다"

    return None


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    root = name.split(".")[0]
    if name not in _ALLOWED_MODULES and root not in _ALLOWED_MODULES:
        raise SandboxViolation(f"허용되지 않은 모듈 import: {name}")
    return builtins.__import__(name, globals, locals, fromlist, level)


def _build_safe_builtins() -> dict:
    safe = {n: getattr(builtins, n) for n in _ALLOWED_BUILTINS if hasattr(builtins, n)}
    safe["__import__"] = _guarded_import
    return safe


def run_code(
    code: str,
    require_output: bool = True,
    pre_checked: bool = False,
    timeout: float = 15.0,
    **namespace,
) -> tuple[str, bool]:
    """코드를 제한된 환경에서 실행하고 (stdout, 성공여부) 를 돌려줍니다.

    require_output:
        조회 코드(pandas)는 print() 출력이 없으면 실패로 봐야 하지만,
        차트 코드(matplotlib)는 원래 stdout 이 비어 있는 것이 정상입니다.

    pre_checked:
        차트 경로는 LLM 코드를 먼저 check_code 로 검사한 뒤 우리가 통제하는
        savefig 구문을 덧붙입니다. 그 뒤 다시 검사하면 우리가 붙인 savefig 가
        걸리므로 정적 검사를 건너뜁니다. 런타임 제한은 그대로 적용됩니다.

    timeout:
        벽시계 기준 실행 상한. 초과하면 실패로 처리합니다. 파이썬에서 스레드를
        강제 종료할 수는 없으므로 폭주한 코드는 계속 돌지만, 앱은 응답을
        돌려주고 사용자는 멈춘 화면을 보지 않습니다.
    """
    if not pre_checked:
        violation = check_code(code)
        if violation:
            return f"SandboxViolation: {violation}", False

    scope = dict(namespace)
    scope["__builtins__"] = _build_safe_builtins()

    buffer = io.StringIO()
    result: dict = {"ok": True}

    def _target() -> None:
        try:
            with contextlib.redirect_stdout(buffer):
                exec(code, scope)  # noqa: S102 - 검사·제한을 통과한 코드만 실행
        except Exception as exc:
            result["ok"] = False
            print(f"{type(exc).__name__}: {exc}", file=buffer)

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(timeout)

    if worker.is_alive():
        return (
            f"TimeoutError: 실행이 {timeout:.0f}초를 넘겨 중단했습니다. "
            "더 단순한 조회로 다시 시도하세요."
        ), False

    output = buffer.getvalue().strip()
    ok = result["ok"]
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
