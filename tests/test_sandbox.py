"""LLM 생성 코드 실행 샌드박스 검증 (LLM 호출 없음)

앱을 공개 배포하므로 프롬프트 인젝션이 곧 임의 코드 실행이 되지 않아야 합니다.

    python -m tests.test_sandbox
"""

import pandas as pd

from utils import run_code

DF = pd.DataFrame({
    "tenant": ["a", "b", "a"],
    "action": ["blocked", "allowed", "flagged"],
    "injection_label": [1, 0, 1],
    "detector_score": [0.9, 0.1, 0.5],
    "latency_ms": [100, 200, 300],
    "timestamp": ["2026-08-01", "2026-08-02", "2026-08-03"],
})

# 반드시 차단되어야 하는 코드
MUST_BLOCK = [
    ("파일 읽기",          "print(open('/etc/passwd').read())"),
    ("os 모듈",           "import os\nprint(os.listdir('/'))"),
    ("subprocess",       "import subprocess\nprint(subprocess.run(['ls']))"),
    ("__import__ 우회",    "print(__import__('os').getcwd())"),
    ("builtins 접근",      "print(__builtins__)"),
    ("클래스 탈출",         "print(().__class__.__bases__[0].__subclasses__())"),
    ("eval",             "print(eval('1+1'))"),
    ("네트워크",            "import requests\nprint(requests.get('http://x'))"),
    ("pd 로 .env 유출",    "print(pd.read_csv('.env', sep='=', header=None))"),
    ("pd 로 환경변수 유출",  "print(pd.read_csv('/proc/self/environ', header=None))"),
    ("pd 파일 쓰기",       "df.to_csv('/tmp/leak.csv')\nprint('x')"),
    ("pd.io 우회",        "print(pd.io.common.get_handle('.env','r'))"),
    ("numpy 파일 I/O",    "import numpy as np\nprint(np.load('x.npy'))"),
    ("임의 경로 savefig",   "import matplotlib.pyplot as plt\nplt.savefig('/tmp/pwn.png')"),
    ("허용목록 밖 import",  "import pathlib\nprint(pathlib.Path('/'))"),
    ("pickle",           "print(pd.read_pickle('/tmp/x'))"),
]

# 반드시 동작해야 하는 정상 분석 코드
MUST_PASS = [
    ("groupby 집계",   "print(df.groupby('tenant')['detector_score'].mean())"),
    ("불리언 필터",     "print(df[df['action'] == 'blocked'].shape[0])"),
    ("미탐 계산",       "print(((df.injection_label == 1) & (df.action == 'allowed')).sum())"),
    ("crosstab",      "print(pd.crosstab(df.injection_label, df.action))"),
    ("to_datetime",   "print(pd.to_datetime(df['timestamp']).dt.date.min())"),
    ("value_counts",  "print(df['action'].value_counts())"),
    ("numpy 통계",     "import numpy as np\nprint(np.mean(df['latency_ms']))"),
]


def main() -> int:
    failures = 0

    print("=== 차단되어야 하는 코드 ===")
    for name, code in MUST_BLOCK:
        out, ok = run_code(code, df=DF.copy(), pd=pd)
        blocked = not ok
        failures += not blocked
        print(f"[{'PASS' if blocked else 'FAIL'}] {name:20} {out[:60]}")

    print("\n=== 동작해야 하는 코드 ===")
    for name, code in MUST_PASS:
        out, ok = run_code(code, df=DF.copy(), pd=pd)
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name:20} {out[:50].replace(chr(10), ' ')}")

    total = len(MUST_BLOCK) + len(MUST_PASS)
    print(f"\n{total - failures}/{total} 통과")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
