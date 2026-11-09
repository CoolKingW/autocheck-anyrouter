import pytest

from core.github_reporter import GitHubReporter
from core.models import AccountResult
from core.privacy_handler import PrivacyHandler
from tests.tools.data_builders import build_account_result


class TestGitHubReporter:
	"""测试 GitHub Actions Step Summary 生成"""

	def _generate_summary(
		self,
		tmp_path,
		monkeypatch: pytest.MonkeyPatch,
		account_results: list[AccountResult],
		show_sensitive_info: bool = False,
	) -> str:
		"""生成 summary 并返回文件内容"""
		summary_file = tmp_path / 'summary.md'
		monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(summary_file))

		reporter = GitHubReporter(PrivacyHandler(show_sensitive_info))
		reporter.generate_summary(
			success_count=sum(1 for acc in account_results if acc.status == 'success'),
			total_count=len(account_results),
			account_results=account_results,
		)

		return summary_file.read_text(encoding='utf-8')

	@pytest.mark.parametrize(
		'auth_failed,expected_title',
		[
			(True, '所有账号登录凭据已失效'),
			(False, '所有账号签到失败'),
		],
	)
	def test_all_failed_distinguishes_credential_failure(
		self,
		tmp_path,
		monkeypatch: pytest.MonkeyPatch,
		auth_failed: bool,
		expected_title: str,
	):
		"""全部失败时区分「凭据失效」与「签到业务失败」"""
		content = self._generate_summary(
			tmp_path,
			monkeypatch,
			[
				build_account_result(name='账号 1', status='failed', auth_failed=auth_failed),
				build_account_result(name='账号 2', status='failed', auth_failed=auth_failed),
			],
		)

		assert expected_title in content

	def test_credential_failure_shows_refresh_hint(self, tmp_path, monkeypatch: pytest.MonkeyPatch):
		"""凭据失效时给出重新获取 cookies 的修复指引"""
		content = self._generate_summary(
			tmp_path,
			monkeypatch,
			[build_account_result(name='账号 1', status='failed', auth_failed=True)],
		)

		assert 'ANYROUTER_ACCOUNT_' in content

	def test_masked_mode_marks_credential_failure_per_account(self, tmp_path, monkeypatch: pytest.MonkeyPatch):
		"""脱敏模式下按账号标注「凭据失效」与普通失败"""
		content = self._generate_summary(
			tmp_path,
			monkeypatch,
			[
				build_account_result(name='账号 1', status='failed', auth_failed=True),
				build_account_result(name='账号 2', status='failed'),
			],
		)

		assert '❌ 凭据失效' in content
		assert '❌ 签到失败' in content

	def test_partial_success_has_no_credential_banner(self, tmp_path, monkeypatch: pytest.MonkeyPatch):
		"""只有一个账号失败时不误报为全部凭据失效"""
		content = self._generate_summary(
			tmp_path,
			monkeypatch,
			[
				build_account_result(name='账号 1', quota=25.0, used=5.0),
				build_account_result(name='账号 2', status='failed', auth_failed=True),
			],
		)

		assert '部分账号签到成功' in content
		assert '所有账号登录凭据已失效' not in content
