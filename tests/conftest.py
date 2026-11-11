"""테스트 공통 설정.

GitHub Actions 에서 테스트가 실패하면 실패 내용을 "주석(annotation)" 으로도 남긴다. 주석은 실행 요약 화면에
바로 보이고 로그를 열지 않아도 확인할 수 있어, 특정 운영체제에서만 실패하는 테스트를 빨리 찾을 수 있다.
"""

import os

import pytest


def _escape(text: str) -> str:
    # 주석 명령에서 줄바꿈과 % 는 따로 적어야 한다
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if not report.failed or not os.environ.get("GITHUB_ACTIONS"):
        return
    path, line, _ = item.location
    detail = str(report.longrepr)[-1500:]   # 맨 끝의 단언 실패 부분이 가장 쓸모 있다
    print(f"\n::error file={path},line={(line or 0) + 1},title={item.nodeid}::{_escape(detail)}")
