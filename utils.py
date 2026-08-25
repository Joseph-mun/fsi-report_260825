"""코드 생성·실행 유틸리티

이 앱은 사용자 질문을 LLM 에 넘겨 pandas/matplotlib 코드를 만든 뒤 실행합니다.
공개 URL 로 배포하므로 **프롬프트 인젝션이 곧 임의 코드 실행**이 되지 않도록
막아야 합니다.

## 왜 허용 목록인가 — 두 번 실패한 뒤 내린 결론

1차: 금지 문자열 목록(블록리스트). 뚫렸다.

    o = pd._libs.pandas.compat.os      # 소스에 'os.' 문자열이 없다
    o.system('...')                    # 그래도 진짜 os 모듈이다

2차: AST 로 밑줄 이름을 막았다. 또 뚫렸다.

    np.lib.npyio.DataSource('.').open('.env').read()   # .env 를 그대로 읽었다
    plt.gcf().canvas.print_png('/tmp/x')               # 임의 경로 파일 쓰기
    np.ctypeslib.load_library(...)                     # ctypes 로더 (Linux 에서 RCE)

"내부로 가는 길은 밑줄을 지난다"는 전제가 numpy/matplotlib 에는 통하지 않는다.
이 패키지들은 **밑줄 없는 공개 속성으로 살아있는 하위 모듈을 그대로 노출**한다.
금지 이름을 하나씩 추가하는 방식은 수렴하지 않는다 — 허용된 패키지마다 공개
하위 모듈이 수십 개씩 있다.

3차(현재): **허용 목록으로 뒤집었다.** 명시적으로 허용한 속성 이름만 쓸 수 있다.
`lib`, `npyio`, `DataSource`, `canvas`, `print_png`, `ctypeslib` 는 목록에 없으므로
자동으로 거부된다. 새로운 하위 모듈이 생겨도 기본값이 '거부'다.

## 방어 구성

1. AST 허용 목록 — 허용한 속성/이름만 통과. import 는 전면 금지
   (pd·np·plt 는 실행 네임스페이스에 미리 넣어 주므로 import 가 필요 없다)
2. 런타임 제한  — 화이트리스트 내장함수만 남긴 네임스페이스
3. 실행 시간 상한 — 15초 초과 시 중단

## 한계 (문서화)

같은 프로세스 안에서 exec 하는 구조 자체의 한계는 남는다. 허용한 pandas 메서드에
새로운 파일 I/O 인자가 생기면 다시 뚫릴 수 있다. 완전한 격리가 필요하면 별도
프로세스 + OS 수준 샌드박스로 가야 한다. 이 앱은 실습 범위이므로 허용 목록으로
공격면을 좁히는 선에서 멈춘다.
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
}

# 코드가 참조할 수 있는 최상위 이름. 실행 네임스페이스에 미리 넣어 줍니다.
_ALLOWED_ROOTS = {"df", "pd", "np", "plt"}

# ---------------------------------------------------------------------------
# 허용 속성 목록
# ---------------------------------------------------------------------------
# 여기 없는 속성 이름은 전부 거부됩니다. 새 하위 모듈이 생겨도 기본값이 '거부'라
# 시간이 지나도 안전합니다. 필요한 분석 기능이 막히면 이 목록에 추가하세요.

_PANDAS_ATTRS = {
    # 선택 · 필터
    "loc", "iloc", "at", "iat", "columns", "index", "values", "shape", "size",
    "dtypes", "T", "empty", "name", "isin", "where", "mask", "filter",
    "head", "tail", "sample", "nlargest", "nsmallest", "first", "last",
    # 집계 · 통계
    "groupby", "agg", "aggregate", "apply", "map", "transform", "pipe",
    "sum", "mean", "median", "min", "max", "std", "var", "count", "size",
    "nunique", "unique", "value_counts", "describe", "quantile", "mode",
    "cumsum", "cumcount", "rank", "corr", "cov", "sem", "prod",
    "idxmax", "idxmin", "any", "all",
    # 변형 · 정렬
    "sort_values", "sort_index", "reset_index", "set_index", "rename",
    "assign", "drop", "dropna", "fillna", "replace", "astype", "copy",
    "pivot_table", "pivot", "melt", "merge", "join", "concat", "crosstab",
    "cut", "qcut", "get_dummies", "to_datetime", "to_numeric", "date_range",
    "round", "abs", "clip", "diff", "shift", "unstack", "stack", "explode",
    "drop_duplicates", "duplicated", "notna", "isna", "isnull", "notnull",
    "reindex", "squeeze", "add_prefix", "add_suffix", "nlargest",
    "DataFrame", "Series", "Timestamp", "Timedelta", "NA", "NaT",
    # 비교 연산 (메서드 형태)
    "eq", "ne", "lt", "le", "gt", "ge", "between", "add", "sub", "mul", "div",
    # 접근자
    "str", "dt", "cat", "sort", "tolist", "to_list", "items", "keys",
    # str 접근자 하위
    "contains", "startswith", "endswith", "lower", "upper", "strip", "len",
    "split", "extract", "replace", "title", "capitalize", "zfill", "slice",
    # dt 접근자 하위
    "year", "month", "day", "hour", "minute", "date", "time", "weekday",
    "dayofweek", "quarter", "days", "total_seconds", "floor", "normalize",
}

_NUMPY_ATTRS = {
    "mean", "median", "std", "var", "sum", "min", "max", "abs", "round",
    "percentile", "quantile", "array", "arange", "linspace", "log", "log10",
    "exp", "sqrt", "where", "unique", "histogram", "corrcoef", "nan",
    "clip", "cumsum", "sort", "argsort", "isnan", "isfinite",
}

_MATPLOTLIB_ATTRS = {
    # pyplot 함수
    "plot", "bar", "barh", "hist", "scatter", "pie", "boxplot", "violinplot",
    "stackplot", "fill_between", "errorbar", "step", "hexbin", "imshow",
    "title", "xlabel", "ylabel", "legend", "grid", "xticks", "yticks",
    "xlim", "ylim", "tight_layout", "subplots", "subplot", "figure", "close",
    "axhline", "axvline", "text", "annotate", "colorbar", "suptitle",
    "set_title", "set_xlabel", "set_ylabel", "set_xticks", "set_xticklabels",
    "set_ylim", "set_xlim", "bar_label", "invert_yaxis", "invert_xaxis",
    # show 는 프롬프트가 코드의 마지막 줄로 요구한다. Agg 백엔드에서는
    # 아무 일도 하지 않고, change_plot_to_save 가 savefig 로 치환한다.
    "show", "gca", "gcf", "sca", "cla", "clf", "axis", "twinx", "twiny",
    # DataFrame.plot 접근자
    "kind", "ax", "figsize", "rot", "color", "alpha", "label", "stacked",
}

# 위 세 묶음의 합집합이 최종 허용 목록입니다.
_ALLOWED_ATTRS = _PANDAS_ATTRS | _NUMPY_ATTRS | _MATPLOTLIB_ATTRS


class SandboxViolation(RuntimeError):
    """생성된 코드가 허용 범위를 벗어났을 때 발생합니다."""


def python_code_parser(text: str) -> str:
    """LLM 응답에서 Python 코드 블록만 추출합니다."""
    processed = text.replace("```python", "```").strip()
    parts = processed.split("```")

    if len(parts) == 1:
        return processed

    return "\n".join(parts[i] for i in range(1, len(parts), 2))


def check_code(code: str, extra_attrs: set[str] | None = None) -> str | None:
    """실행 전 구조 검사. 문제가 있으면 사유 문자열, 없으면 None.

    extra_attrs:
        CSV 열 이름처럼 이 데이터셋에서만 유효한 속성. `df.tenant` 같은
        열 접근을 허용하기 위해 호출부가 넘겨 줍니다.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"구문 오류: {exc.msg} (line {exc.lineno})"

    allowed_attrs = _ALLOWED_ATTRS | (extra_attrs or set())
    # 코드가 스스로 만든 지역 변수는 참조를 허용해야 합니다.
    assigned: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            assigned.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assigned.add(node.name)
            for a in node.args.args + node.args.kwonlyargs:
                assigned.add(a.arg)
        elif isinstance(node, ast.Lambda):
            for a in node.args.args + node.args.kwonlyargs:
                assigned.add(a.arg)
        elif isinstance(node, ast.comprehension):
            for t in ast.walk(node.target):
                if isinstance(t, ast.Name):
                    assigned.add(t.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            assigned.add(node.name)

    for node in ast.walk(tree):
        # 1) 속성 접근 — 허용 목록에 있는 이름만 통과시킨다.
        #    np.lib / npyio / DataSource / canvas / print_png / ctypeslib 처럼
        #    밑줄 없이 공개된 하위 모듈이 여기서 전부 걸린다.
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                return f"내부 속성 접근 금지: .{node.attr}"
            if node.attr not in allowed_attrs:
                return (
                    f"허용되지 않은 속성: .{node.attr} "
                    "(데이터 조회·차트에 필요한 속성만 사용할 수 있습니다)"
                )

        # 2) 이름 참조 — 허용 루트, 내장 함수, 코드가 만든 변수만
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id.startswith("_"):
                return f"내부 이름 사용 금지: {node.id}"
            if node.id not in _ALLOWED_ROOTS | _ALLOWED_BUILTINS | assigned:
                return f"허용되지 않은 이름: {node.id}"

        # 3) import 전면 금지 — pd·np·plt 는 이미 네임스페이스에 있다.
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return "import 는 필요하지 않습니다 (df, pd, np, plt 가 이미 준비되어 있습니다)"

        # 4) while 루프 금지 — 데이터 조회·차트에 필요 없고,
        #    무한 루프로 공개 앱을 멈춰 세우는 가장 쉬운 수단이다.
        if isinstance(node, ast.While):
            return "while 루프는 허용되지 않습니다 (pandas 연산을 사용하세요)"

        # 5) class 정의 금지 — 메서드 해석 순서를 타고 내려가는 우회의 출발점
        if isinstance(node, ast.ClassDef):
            return "class 정의는 허용되지 않습니다"

    return None


def _build_safe_builtins() -> dict:
    safe = {n: getattr(builtins, n) for n in _ALLOWED_BUILTINS if hasattr(builtins, n)}
    return safe


def run_code(
    code: str,
    require_output: bool = True,
    pre_checked: bool = False,
    timeout: float = 15.0,
    extra_attrs: set[str] | None = None,
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
        violation = check_code(code, extra_attrs)
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
