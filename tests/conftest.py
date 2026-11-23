"""테스트 공통 설정.

GitHub Actions 에서 테스트가 실패하면 실패 내용을 "주석(annotation)" 으로도 남긴다. 주석은 실행 요약 화면에
바로 보이고 로그를 열지 않아도 확인할 수 있어, 특정 운영체제에서만 실패하는 테스트를 빨리 찾을 수 있다.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def _no_external_tools(monkeypatch):
    """기본은 외부 도구를 끈다. 리눅스 CI 처럼 file·strings 가 깔린 환경에서도 결과가 같게 하려는 것.
    외부 도구 테스트(test_external_v027.py)는 이 값을 지우고 가짜 실행 파일만 있는 PATH 를 쓴다."""
    monkeypatch.setenv("CTFKIT_NO_EXTERNAL", "1")


@pytest.fixture(autouse=True)
def _no_contest_settings(monkeypatch):
    """기본은 대회 설정 파일(.ctfkit.json)을 찾지 않는다. 저장소 위 폴더에 설정 파일이 있어도 결과가 같게.
    설정 테스트(test_config_v029.py)는 이 값을 지운다. 설정은 프로세스 안에서 캐시하므로 테스트마다 비운다."""
    from ctfkit import settings

    monkeypatch.setenv("CTFKIT_CONFIG", "none")
    settings.reset()
    yield
    settings.reset()


@pytest.fixture(autouse=True)
def _human_output(monkeypatch):
    """기본은 사람용 출력이다. Claude Code 안에서 테스트를 돌리면 CLAUDECODE 가 있어 start 가 에이전트 모드가 되므로 끈다.
    실행 환경 안내도 테스트 PC 마다 달라지므로 기본은 빈 목록으로 둔다 (test_agent_mode_v031.py 가 따로 검사)."""
    monkeypatch.setenv("CTFKIT_AGENT", "0")
    monkeypatch.setattr("ctfkit.commands.start.environment_lines", lambda: [])


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
