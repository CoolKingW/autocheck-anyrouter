import json

from core.checkin_service import CheckinService
from tests.fixtures.mock_dependencies import MockHttpClient

AGENT_ACCOUNT = {
	'name': 'Agent',
	'cookies': {'session': 'agent_session'},
	'api_user': '101',
	'base_url': 'https://agentrouter.org/',
	'sign_in_path': None,
	'proxy': 'http://user:pass@127.0.0.1:5380',
	'required_waf_cookies': ['acw_tc'],
}


class TestDescribeResponseFailure:
	"""测试从响应体中提取失败原因"""

	def test_extracts_message_from_json_body(self):
		"""JSON 响应优先取 message 字段"""
		response = MockHttpClient.build_response(
			status=401,
			json_data={'success': False, 'message': '未登录且未提供 access token'},
		)

		assert '未登录且未提供 access token' in CheckinService._describe_response_failure(response)

	def test_falls_back_to_msg_field(self):
		"""没有 message 时退化为 msg 字段"""
		response = MockHttpClient.build_response(
			status=500,
			json_data={'msg': '服务器内部错误'},
		)

		assert '服务器内部错误' in CheckinService._describe_response_failure(response)

	def test_non_json_body_reports_possible_waf_block(self):
		"""解析失败的响应（WAF 挑战页）只提示类型，不把 HTML 刷进日志"""
		response = MockHttpClient.build_response(
			status=200,
			text='<html><script>var arg1=1</script></html>',
			json_error=json.JSONDecodeError('Expecting value', '<html>', 0),
		)

		reason = CheckinService._describe_response_failure(response)

		assert 'WAF' in reason
		assert '<html>' not in reason

	def test_empty_json_body_returns_no_reason(self):
		"""JSON 能解析但没有说明字段时不应误判成 WAF 拦截"""
		response = MockHttpClient.build_response(
			status=401,
			text='{}',
		)

		assert CheckinService._describe_response_failure(response) == ''

	def test_returns_empty_string_without_reason(self):
		"""无法提取原因时返回空字符串"""
		response = MockHttpClient.build_response(status=401)

		assert CheckinService._describe_response_failure(response) == ''


class TestSiteConfig:
	"""测试多站点配置解析（新增字段全部可选，旧配置保持默认行为）"""

	def test_defaults_keep_anyrouter_behaviour(self):
		"""未配置新字段时沿用 AnyRouter 默认值"""
		site = CheckinService()._resolve_site_config({'cookies': 'session=1', 'api_user': '1'})

		assert site.base_url == 'https://anyrouter.top'
		assert site.login_url == 'https://anyrouter.top/login'
		assert site.console_url == 'https://anyrouter.top/console'
		assert site.user_info_url == 'https://anyrouter.top/api/user/self'
		assert site.sign_in_url == 'https://anyrouter.top/api/user/sign_in'
		assert site.proxy is None
		assert site.required_waf_cookies == ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2']

	def test_visit_mode_when_sign_in_path_is_null(self):
		"""sign_in_path 显式为 null 表示该站点无签到接口（访问即签到）"""
		site = CheckinService()._resolve_site_config(AGENT_ACCOUNT)

		assert site.base_url == 'https://agentrouter.org'
		assert site.login_url == 'https://agentrouter.org/login'
		assert site.sign_in_url is None
		assert site.proxy == 'http://user:pass@127.0.0.1:5380'
		assert site.required_waf_cookies == ['acw_tc']

	def test_custom_sign_in_path(self):
		"""可自定义签到接口路径"""
		site = CheckinService()._resolve_site_config({
			'cookies': 'session=1',
			'api_user': '1',
			'sign_in_path': '/api/user/checkin',
		})  # fmt: skip

		assert site.sign_in_url == 'https://anyrouter.top/api/user/checkin'

	def test_empty_sign_in_path_disables_sign_in(self):
		"""空字符串同样视为无签到接口"""
		site = CheckinService()._resolve_site_config({
			'cookies': 'session=1',
			'api_user': '1',
			'sign_in_path': '',
		})  # fmt: skip

		assert site.sign_in_url is None

	def test_playwright_proxy_parsing(self):
		"""代理 URL 转 Playwright proxy 配置"""
		assert CheckinService._build_playwright_proxy(None) is None
		assert CheckinService._build_playwright_proxy('http://10.0.0.1') is None  # 缺少端口

		assert CheckinService._build_playwright_proxy('http://user:p%40ss@10.0.0.1:1080') == {
			'server': 'http://10.0.0.1:1080',
			'username': 'user',
			'password': 'p@ss',
		}
