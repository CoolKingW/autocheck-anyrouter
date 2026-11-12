import os
from contextlib import ExitStack
from unittest.mock import patch

import pytest

from application import Application
from tests.fixtures.mock_dependencies import MockHttpClient, MockPlaywright

# 无签到接口的站点（访问即签到），只下发 acw_tc 一个 WAF cookie
AGENT_ACCOUNT = {
	'name': 'Agent',
	'cookies': {'session': 'agent_session'},
	'api_user': '101',
	'base_url': 'https://agentrouter.org',
	'sign_in_path': None,
	'required_waf_cookies': ['acw_tc'],
}

# 仅用访问令牌（不提供 session cookie）的账号
AGENT_TOKEN_ACCOUNT = {
	'name': 'Agent-Token',
	'api_user': '809242',
	'access_token': 'agent_token_value',
	'base_url': 'https://agentrouter.org',
	'sign_in_path': None,
	'required_waf_cookies': ['acw_tc'],
}


class TestMultiSiteCheckin:
	"""测试多站点配置（base_url / sign_in_path / required_waf_cookies）"""

	@pytest.mark.asyncio
	async def test_visit_mode_completes_without_sign_in_api(self, accounts_env, tmp_path):
		"""sign_in_path 为 null 时用访问触发签到，不应发起签到接口请求"""
		accounts_env([AGENT_ACCOUNT])

		app = Application()
		app.balance_manager.balance_hash_file = tmp_path / 'hash_agent.txt'
		summary_file = tmp_path / 'summary_agent.md'

		post_count = {'n': 0}

		async def post_handler(*args, **kwargs):
			post_count['n'] += 1
			return MockHttpClient.build_response(status=200, json_data={'ret': 1})

		with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary_file)}):
			with ExitStack() as stack:
				# 只下发 acw_tc，验证 required_waf_cookies 生效
				MockPlaywright.setup_success(
					stack,
					cookies=[{'name': 'acw_tc', 'value': 'mock_acw_tc'}],
				)
				MockHttpClient.setup(stack, MockHttpClient.get_success_handler, post_handler)

				with pytest.raises(SystemExit) as exc_info:
					await app.run()

		assert exc_info.value.code == 0, '访问即签到成功时应该正常退出'
		assert post_count['n'] == 0, '该站点没有签到接口，不应发起 POST 请求'
		assert summary_file.exists()

	@pytest.mark.asyncio
	async def test_visit_mode_marks_credential_failure(self, accounts_env, tmp_path):
		"""访问模式下 401 同样被判为凭据失效"""
		accounts_env([AGENT_ACCOUNT])

		app = Application()
		app.balance_manager.balance_hash_file = tmp_path / 'hash_agent_401.txt'
		summary_file = tmp_path / 'summary_agent_401.md'

		unauthorized = {'success': False, 'message': '未登录且未提供 access token'}

		async def get_handler(*args, **kwargs):
			return MockHttpClient.build_response(status=401, json_data=unauthorized)

		with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary_file)}):
			with ExitStack() as stack:
				MockPlaywright.setup_success(
					stack,
					cookies=[{'name': 'acw_tc', 'value': 'mock_acw_tc'}],
				)
				MockHttpClient.setup(stack, get_handler, MockHttpClient.post_success_handler)

				with pytest.raises(SystemExit) as exc_info:
					await app.run()

		assert exc_info.value.code == 1, '凭据失效时应该以失败退出'

		content = summary_file.read_text(encoding='utf-8')
		assert '所有账号登录凭据已失效' in content

	@pytest.mark.asyncio
	async def test_token_only_account_without_cookies(self, accounts_env, tmp_path):
		"""只有 access_token、没有 cookies 时也能签到，并携带 Bearer 与 new-api-user 头"""
		accounts_env([AGENT_TOKEN_ACCOUNT])

		app = Application()
		app.balance_manager.balance_hash_file = tmp_path / 'hash_agent_token.txt'

		captured = {}

		async def get_handler(*args, **kwargs):
			captured['headers'] = kwargs.get('headers', {})
			return MockHttpClient.build_response(
				status=200,
				json_data={'success': True, 'data': {'quota': 25000000, 'used_quota': 5000000}},
			)

		with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': '/dev/null'}):
			with ExitStack() as stack:
				MockPlaywright.setup_success(
					stack,
					cookies=[{'name': 'acw_tc', 'value': 'mock_acw_tc'}],
				)
				MockHttpClient.setup(stack, get_handler, MockHttpClient.post_success_handler)

				with pytest.raises(SystemExit) as exc_info:
					await app.run()

		assert exc_info.value.code == 0, '令牌有效时应该正常退出'
		assert captured['headers']['Authorization'] == 'Bearer agent_token_value'
		assert captured['headers']['new-api-user'] == '809242'
