"""허용 목록 전수 감사 (LLM 호출 없음)

허용한 속성 중에 파일을 쓸 수 있는 경로가 하나라도 있으면 실패합니다.
샌드박스에서 반복적으로 뚫렸던 두 가지 부류를 자동으로 잡습니다.

  1. 파일·경로 인자를 받는 메서드      (df.to_string(buf=...) 부류)
  2. 문자열을 메서드 이름으로 해석하는 메서드 (df.agg('to_csv', ...) 부류)

허용 목록에 새 이름을 추가할 때 이 테스트를 돌리면,
그 이름이 위 두 부류에 속하는지 자동으로 알려 줍니다.

    python -m tests.test_allowlist_audit
"""

import inspect
import os
import tempfile
import warnings

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")

# 감사 과정에서 pandas 미래 버전 경고가 대량으로 나옵니다 (기능과 무관).
warnings.simplefilter("ignore")

from utils import _ALLOWED_ATTRS  # noqa: E402

# 파일 경로를 받는 대표적인 인자 이름
FILE_PARAMS = {
    "path", "buf", "path_or_buf", "fname", "file", "filename", "excel_writer",
    "filepath_or_buffer", "stream", "dest", "target", "path_or_buffer",
}

DF = pd.DataFrame({
    "tenant": ["a", "b", "a"],
    "action": ["blocked", "allowed", "flagged"],
    "injection_label": [1, 0, 1],
    "detector_score": [0.9, 0.1, 0.5],
    "latency_ms": [100, 200, 300],
})


def audit_file_params() -> list[str]:
    """허용 속성 중 파일·경로 인자를 받는 것을 찾습니다."""
    hits = []
    for name in sorted(_ALLOWED_ATTRS):
        for owner, label in ((pd, "pd"), (pd.DataFrame, "DataFrame"),
                             (pd.Series, "Series"), (np, "np")):
            fn = getattr(owner, name, None)
            if fn is None or not callable(fn):
                continue
            try:
                params = set(inspect.signature(fn).parameters)
            except (ValueError, TypeError):
                continue
            overlap = FILE_PARAMS & params
            if overlap:
                hits.append(f"{label}.{name} (인자: {sorted(overlap)})")
            break
    return hits


def audit_string_dispatch() -> list[str]:
    """허용 속성 중 문자열을 메서드 이름으로 해석해 파일을 쓰는 것을 찾습니다."""
    hits = []
    series = DF["latency_ms"]
    grouped = DF.groupby("tenant")

    with tempfile.TemporaryDirectory() as tmp:
        for name in sorted(_ALLOWED_ATTRS):
            for obj, label in ((DF, "DataFrame"), (series, "Series"),
                               (grouped, "GroupBy")):
                fn = getattr(obj, name, None)
                if fn is None or not callable(fn):
                    continue
                path = os.path.join(tmp, f"{label}_{name}")
                for call in (
                    lambda f=fn, p=path: f("to_csv", args=(p,)),
                    lambda f=fn, p=path: f("to_csv", path_or_buf=p),
                    lambda f=fn, p=path: f("to_csv", 0, p),
                ):
                    try:
                        call()
                    except Exception:
                        pass
                    if os.path.exists(path):
                        hits.append(f"{label}.{name}")
                        os.remove(path)
                        break
                if hits and hits[-1].endswith(f".{name}"):
                    break
    return hits


def main() -> int:
    failures = 0

    file_hits = audit_file_params()
    print("=== 파일·경로 인자를 받는 허용 속성 ===")
    if file_hits:
        failures += 1
        for h in file_hits:
            print(f"  [FAIL] {h}")
    else:
        print("  [PASS] 없음")

    dispatch_hits = audit_string_dispatch()
    print("\n=== 문자열을 메서드로 해석하는 허용 속성 ===")
    if dispatch_hits:
        failures += 1
        for h in dispatch_hits:
            print(f"  [FAIL] {h}")
    else:
        print("  [PASS] 없음")

    print(f"\n검사한 허용 속성: {len(_ALLOWED_ATTRS)}개")
    print("전수 감사 통과" if not failures else "전수 감사 실패")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
