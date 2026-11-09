import json

from core.checkin_service import CheckinService
from tests.fixtures.mock_dependencies import MockHttpClient


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
