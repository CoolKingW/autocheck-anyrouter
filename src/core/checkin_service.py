import json
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlparse

import httpx
from playwright.async_api import async_playwright

from core.privacy_handler import PrivacyHandler
from tools.logger import logger


@dataclass
class SiteConfig:
	"""站点与网络配置（均可在账号 JSON 中覆盖，缺省时沿用 AnyRouter 默认值）"""

	base_url: str
	login_url: str
	console_url: str
	user_info_url: str
	login_api_url: str

	# 签到接口，None 表示该站点没有独立签到接口（访问即签到）
	sign_in_url: str | None

	# 出口代理，形如 http://user:pass@host:port
	proxy: str | None = None

	# 必需的 WAF cookie 名称
	required_waf_cookies: list[str] = field(default_factory=list)


class CheckinService:
	"""AnyRouter 签到服务"""

	class Config:
		"""服务配置"""

		class URLs:
			"""URL 配置"""

			BASE = 'https://anyrouter.top'
			LOGIN_PATH = '/login'
			CONSOLE_PATH = '/console'
			USER_INFO_PATH = '/api/user/self'
			LOGIN_API_PATH = '/api/user/login'
			SIGN_IN_PATH = '/api/user/sign_in'

			LOGIN = f'{BASE}{LOGIN_PATH}'
			API_BASE = f'{BASE}/api'
			USER_INFO = f'{BASE}{USER_INFO_PATH}'
			CHECKIN = f'{BASE}{SIGN_IN_PATH}'
			CONSOLE = f'{BASE}{CONSOLE_PATH}'

		class Env:
			"""环境变量配置"""

			ACCOUNTS_KEY = 'ANYROUTER_ACCOUNTS'
			ACCOUNT_PREFIX = 'ANYROUTER_ACCOUNT_'
			SHOW_SENSITIVE_INFO = 'SHOW_SENSITIVE_INFO'
			REPO_VISIBILITY = 'REPO_VISIBILITY'
			ACTIONS_RUNNER_DEBUG = 'ACTIONS_RUNNER_DEBUG'
			GITHUB_STEP_SUMMARY = 'GITHUB_STEP_SUMMARY'
			CI = 'CI'
			GITHUB_ACTIONS = 'GITHUB_ACTIONS'

		class File:
			"""文件配置"""

			BALANCE_HASH_NAME = 'balance_hash.txt'

		class Browser:
			"""浏览器配置"""

			USER_AGENT_PARTS = [
				'Mozilla/5.0',
				'(Windows NT 10.0; Win64; x64)',
				'AppleWebKit/537.36',
				'(KHTML, like Gecko)',
				'Chrome/138.0.0.0',
				'Safari/537.36',
			]
			ARGS = [
				'--disable-blink-features=AutomationControlled',
				'--disable-dev-shm-usage',
				'--disable-web-security',
				'--disable-features=VizDisplayCompositor',
				'--no-sandbox',
			]

		class WAF:
			"""WAF 配置"""

			COOKIE_NAMES = ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2']

	def _resolve_site_config(self, account_info: dict[str, Any]) -> SiteConfig:
		"""
		解析账号的站点与网络配置

		支持的字段（均可缺省，旧配置无需修改）：
		- base_url: 站点根地址，默认 https://anyrouter.top
		- sign_in_path: 签到接口路径，显式传 null/空字符串表示无签到接口（访问即签到）
		- proxy: 出口代理，形如 http://user:pass@host:port
		- required_waf_cookies: 必需的 WAF cookie 名称，默认 acw_tc/cdn_sec_tc/acw_sc__v2
		- username/password: 站点要求「重新登录才到账」时使用，配置后每次运行都会真实登录一次
		"""
		base_url = (account_info.get('base_url') or self.Config.URLs.BASE).rstrip('/')

		# 未配置时沿用默认签到接口；显式配置为空表示签到由访问触发
		if 'sign_in_path' in account_info:
			sign_in_path = account_info.get('sign_in_path')
		else:
			sign_in_path = self.Config.URLs.SIGN_IN_PATH

		required_waf_cookies = account_info.get('required_waf_cookies') or self.Config.WAF.COOKIE_NAMES
		if isinstance(required_waf_cookies, str):
			required_waf_cookies = [required_waf_cookies]

		return SiteConfig(
			base_url=base_url,
			login_url=f'{base_url}{self.Config.URLs.LOGIN_PATH}',
			console_url=f'{base_url}{self.Config.URLs.CONSOLE_PATH}',
			user_info_url=f'{base_url}{self.Config.URLs.USER_INFO_PATH}',
			login_api_url=f'{base_url}{self.Config.URLs.LOGIN_API_PATH}',
			sign_in_url=f'{base_url}{sign_in_path}' if sign_in_path else None,
			proxy=account_info.get('proxy') or None,
			required_waf_cookies=list(required_waf_cookies),
		)

	@staticmethod
	def _build_playwright_proxy(proxy: str | None) -> Any:
		"""
		把代理 URL 转成 Playwright 需要的 proxy 配置

		注意：Chromium 不支持 SOCKS5 认证，带账号密码的 SOCKS5 代理需要改用其 HTTP 端口
		"""
		if not proxy:
			return None

		parsed = urlparse(proxy)
		if not parsed.hostname or not parsed.port:
			return None

		scheme = (parsed.scheme or 'http').lower()
		config: dict[str, Any] = {'server': f'{scheme}://{parsed.hostname}:{parsed.port}'}

		if parsed.username:
			config['username'] = unquote(parsed.username)
		if parsed.password:
			config['password'] = unquote(parsed.password)

		return config

	@staticmethod
	def _is_auto_user(api_user: Any) -> bool:
		"""api_user 为 auto 时表示不发送 new-api-user 头，直接用 session 自身身份"""
		return str(api_user or '').strip().lower() == 'auto'

	def _build_headers(self, site: SiteConfig, api_user: Any, access_token: Any = None) -> dict[str, str]:
		"""构造 API 请求头；api_user 为 auto 时省略 new-api-user，access_token 存在时使用 Bearer 鉴权"""
		headers = {
			'User-Agent': ' '.join(self.Config.Browser.USER_AGENT_PARTS),
			'Referer': site.console_url,
			'Origin': site.base_url,
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
		}

		if not self._is_auto_user(api_user):
			headers['new-api-user'] = str(api_user)

		if access_token:
			headers['Authorization'] = f'Bearer {access_token}'

		return headers

	async def check_in_account(
		self,
		account_info: dict[str, Any],
		account_index: int,
	) -> tuple[bool, dict[str, Any] | None]:
		"""
		为单个账号执行签到操作

		Args:
		    account_info: 账号配置信息
		    account_index: 账号索引

		Returns:
		    tuple[bool, dict[str, Any] | None]: (是否签到成功, 用户信息)
		"""
		privacy_handler = PrivacyHandler(PrivacyHandler.should_show_sensitive_info())
		account_name = privacy_handler.get_safe_account_name(account_info, account_index)
		logger.processing(f'开始处理 {account_name}')

		# 解析站点与网络配置（base_url / proxy / sign_in_path 均可缺省）
		site = self._resolve_site_config(account_info)
		logger.debug(
			message=f'站点 {site.base_url}，代理 {"已启用" if site.proxy else "未启用"}',
			tag='配置',
			account_name=account_name,
		)

		# 解析账号配置
		cookies_data = account_info.get('cookies', {})
		api_user = account_info.get('api_user', '')
		access_token = account_info.get('access_token') or account_info.get('token')
		login_username = account_info.get('username') or account_info.get('email')
		login_password = account_info.get('password')

		# 未找到 API 用户标识符
		if not api_user:
			logger.error('未找到 API 用户标识符', account_name)
			return False, None

		# api_user 为 auto 时直接用 session 自身身份
		if self._is_auto_user(api_user):
			logger.debug(
				message='使用 session 身份（未发送 new-api-user 头）',
				tag='配置',
				account_name=account_name,
			)
		# 解析用户 cookies（使用 access_token 或账号密码登录时 cookies 可不填）
		user_cookies = self._parse_cookies(cookies_data)
		login_enabled = bool(login_username and login_password)
		if not user_cookies and not access_token and not login_enabled:
			logger.error('配置格式无效（缺少 cookies / access_token / username+password）', account_name)
			return False, None

		# 步骤1：获取 WAF cookies
		waf_cookies = await self._get_waf_cookies_with_playwright(account_name, site)
		if not waf_cookies:
			logger.error('无法获取 WAF cookies', account_name)
			return False, None

		# 步骤2：使用 httpx 进行 API 请求（代理与浏览器保持一致）
		async with httpx.AsyncClient(http2=True, timeout=30.0, proxy=site.proxy) as client:
			try:
				# 合并 WAF cookies 和用户 cookies
				all_cookies = {**waf_cookies, **user_cookies}
				client.cookies.update(all_cookies)

				headers = self._build_headers(site, api_user, access_token)

				# 站点要求在登录流程中才发放奖励时，先执行一次真实登录
				if login_enabled:
					login_result = await self._login_with_password(
						client=client,
						site=site,
						headers=headers,
						username=str(login_username),
						password=str(login_password),
					)
					if not login_result.get('success'):
						logger.error(login_result.get('error', '登录失败'), account_name)
						return False, login_result

					logger.success('重新登录成功，签到奖励已触发', account_name)

					user_info = await self._get_user_info(
						client=client,
						url=site.user_info_url,
						headers=headers,
						privacy_handler=privacy_handler,
					)
					if user_info and user_info.get('success'):
						logger.info(user_info['display'], account_name)
					else:
						logger.warning((user_info or {}).get('error', '登录后获取用户信息失败'), account_name)

					return True, user_info or {'success': True}

				# 获取用户信息
				user_info = await self._get_user_info(
					client=client,
					url=site.user_info_url,
					headers=headers,
					privacy_handler=privacy_handler,
				)
				if user_info and user_info.get('success'):
					logger.info(user_info['display'], account_name)
				elif user_info:
					logger.warning(user_info.get('error', '未知错误'), account_name)

				# 该站点没有独立签到接口，访问（查询用户信息）即完成签到
				if site.sign_in_url is None:
					if user_info and user_info.get('success'):
						logger.success('查询成功（未配置 username/password，余额不会到账）', account_name)
						return True, user_info

					error_msg = (user_info or {}).get('error', '未知错误')
					logger.error(f'访问签到失败 - {error_msg}', account_name)
					return False, user_info

				sign_in_url = site.sign_in_url

				logger.debug(
					message='执行签到',
					tag='网络',
					account_name=account_name,
				)

				# 更新签到请求头
				checkin_headers = headers.copy()
				checkin_headers.update({
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest'
				})  # fmt: skip

				response = await client.post(
					url=sign_in_url,
					headers=checkin_headers,
					timeout=30,
				)

				logger.debug(
					message=f'响应状态码 {response.status_code}',
					tag='响应',
					account_name=account_name,
				)

				# HTTP 请求失败
				if response.status_code != 200:
					reason = self._describe_response_failure(response)
					logger.error(f'签到失败 - HTTP {response.status_code}{reason}', account_name)

					# 401 说明 session 已失效，需要把原因带回去，供 summary 区分凭据问题
					failed_user_info = dict(user_info) if user_info else {}
					failed_user_info['auth_failed'] = response.status_code == 401
					failed_user_info.setdefault('error', f'签到失败：HTTP {response.status_code}{reason}')
					return False, failed_user_info

				# 处理响应结果
				try:
					result = response.json()
					if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
						logger.success('签到成功!', account_name)
						return True, user_info

					# 签到失败
					error_msg = result.get('msg', result.get('message', '未知错误'))
					logger.error(f'签到失败 - {error_msg}', account_name)
					return False, user_info

				except json.JSONDecodeError:
					# 如果不是 JSON 响应，检查是否包含成功标识
					if 'success' in response.text.lower():
						logger.success('签到成功!', account_name)
						return True, user_info

					# 签到失败
					logger.error('签到失败 - 无效响应格式', account_name)
					return False, user_info

			except Exception as e:
				logger.error(
					message=f'签到过程中发生错误 - {str(e)[:50]}...',
					account_name=account_name,
					exc_info=True,
				)
				return False, None

	async def _get_waf_cookies_with_playwright(
		self,
		account_name: str,
		site: SiteConfig,
	) -> dict[str, str] | None:
		"""
		使用 Playwright 获取 WAF cookies（无痕模式）

		Args:
		    account_name: 账号名称（用于日志）
		    site: 站点与网络配置

		Returns:
		    dict[str, str] | None: WAF cookies 字典，失败返回 None
		"""
		logger.processing('正在启动浏览器获取 WAF cookies...', account_name)

		proxy_config = self._build_playwright_proxy(site.proxy)
		if proxy_config and proxy_config['server'].startswith('socks5') and proxy_config.get('username'):
			logger.warning(
				'Chromium 不支持 SOCKS5 认证，请改用同一代理的 HTTP 端口',
				account_name,
			)

		browser = None
		context = None

		try:
			async with async_playwright() as p:
				# 检测是否在 CI 环境中运行
				is_ci = any(
					os.getenv(env) == 'true'
					for env in (self.Config.Env.CI, self.Config.Env.GITHUB_ACTIONS)
				)  # fmt: skip

				# 使用标准无痕模式，避免临时目录的潜在问题
				# CI 环境使用 headless 模式，本地开发可以看到浏览器界面
				browser = await p.chromium.launch(
					headless=is_ci,
					args=self.Config.Browser.ARGS,
					proxy=proxy_config,
				)

				context = await browser.new_context(
					user_agent=' '.join(self.Config.Browser.USER_AGENT_PARTS),
					viewport={'width': 1920, 'height': 1080},
				)

				page = await context.new_page()

				logger.processing('步骤 1: 访问登录页面获取初始 cookies...', account_name)

				await page.goto(site.login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await context.cookies()

				# 收集所有已知的 WAF cookie，但只强制要求站点声明的必需项
				wanted_cookies = set(self.Config.WAF.COOKIE_NAMES) | set(site.required_waf_cookies)
				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in wanted_cookies and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				logger.info(f'步骤 1 后获得 {len(waf_cookies)} 个 WAF cookies', account_name)

				missing_cookies = [c for c in site.required_waf_cookies if c not in waf_cookies]

				if missing_cookies:
					logger.error(f'缺少 WAF cookies: {missing_cookies}', account_name)
					return None

				logger.success('成功获取所有 WAF cookies', account_name)

				return waf_cookies

		except Exception as e:
			logger.error(
				message=f'获取 WAF cookies 时发生错误：{e}',
				account_name=account_name,
				exc_info=True,
			)
			return None

		finally:
			# 确保资源被正确释放
			if context:
				try:
					await context.close()
				except Exception:
					pass
			if browser:
				try:
					await browser.close()
				except Exception:
					pass

	@staticmethod
	def _describe_response_failure(response: Any) -> str:
		"""
		从响应体中提取失败原因，便于在日志与 summary 中直接看到服务端的说明

		Args:
		    response: HTTP 响应对象

		Returns:
		    str: 形如「（未登录且未提供 access token）」的说明，无法提取时返回空字符串
		"""
		try:
			data = response.json()
		except Exception:
			data = None

		if isinstance(data, dict):
			for key in ('message', 'msg', 'error'):
				reason = data.get(key)
				if reason:
					return f'（{str(reason)[:80]}）'

			# JSON 能解析但没有说明字段（如空对象），不要误判成 WAF 拦截
			return ''

		# 解析失败通常是 WAF 挑战页，只提示类型，避免把 HTML 刷进日志
		if (getattr(response, 'text', None) or '').strip():
			return '（响应不是 JSON，可能是 WAF 挑战页）'

		return ''

	async def _login_with_password(
		self,
		client,
		site: SiteConfig,
		headers: dict[str, str],
		username: str,
		password: str,
	) -> dict[str, Any]:
		"""
		用账号密码执行一次真实登录

		new-api 的「登录即签到」只在登录流程里发放奖励，单纯查询接口不会到账，
		因此配置了 username + password 的账号每次运行都重新登录一次。

		Args:
		    client: httpx 客户端（登录成功后 session cookie 会自动保存在客户端）
		    site: 站点与网络配置
		    headers: 通用请求头
		    username: 登录用户名或邮箱
		    password: 登录密码

		Returns:
		    dict[str, Any]: {'success': True} 或 {'success': False, 'error': ...}
		"""
		login_headers = headers.copy()
		login_headers.pop('new-api-user', None)
		login_headers.pop('Authorization', None)
		login_headers.update({
			'Content-Type': 'application/json',
			'X-Requested-With': 'XMLHttpRequest',
			'Referer': site.login_url,
		})  # fmt: skip

		try:
			response = await client.post(
				url=site.login_api_url,
				headers=login_headers,
				json={'username': username, 'password': password},
				timeout=30,
			)
		except httpx.TimeoutException:
			return {'success': False, 'error': '登录失败：请求超时'}
		except httpx.RequestError:
			return {'success': False, 'error': '登录失败：网络错误'}

		if response.status_code != 200:
			reason = self._describe_response_failure(response)
			return {'success': False, 'error': f'登录失败：HTTP {response.status_code}{reason}'}

		try:
			data = response.json()
		except json.JSONDecodeError:
			reason = self._describe_response_failure(response)
			return {'success': False, 'error': f'登录失败：无效的 JSON 响应{reason}'}

		if isinstance(data, dict) and data.get('success'):
			return {'success': True}

		message = ''
		if isinstance(data, dict):
			message = str(data.get('message') or data.get('msg') or '')

		return {'success': False, 'error': f'登录失败：{message or "账号或密码错误"}'}

	async def _get_user_info(
		self,
		client,
		url: str,
		headers: dict[str, str],
		privacy_handler: PrivacyHandler,
	) -> dict[str, Any]:
		"""
		获取用户信息

		Args:
		    client: httpx 客户端
		    url: 用户信息接口地址
		    headers: 请求头
		    privacy_handler: 隐私处理器

		Returns:
		    dict[str, Any]: 用户信息字典
		"""
		try:
			response = await client.get(
				url=url,
				headers=headers,
				timeout=30,
			)

			# HTTP 请求失败
			if response.status_code != 200:
				reason = self._describe_response_failure(response)
				return {
					'success': False,
					'auth_failed': response.status_code == 401,
					'error': f'获取用户信息失败：HTTP {response.status_code}{reason}',
				}

			# JSON 解析失败（通常是 WAF 挑战页）
			try:
				data = response.json()
			except json.JSONDecodeError:
				reason = self._describe_response_failure(response)
				return {
					'success': False,
					'error': f'获取用户信息失败：无效的 JSON 响应{reason}',
				}

			# API 响应失败
			if not data.get('success'):
				return {
					'success': False,
					'error': data.get('message', '获取用户信息失败：API 错误'),
				}

			# 成功获取用户信息
			user_data = data.get('data', {})
			quota = round(user_data.get('quota', 0) / 500000, 2)
			used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
			return {
				'success': True,
				'quota': quota,
				'used_quota': used_quota,
				'display': privacy_handler.get_safe_balance_display(quota=quota, used=used_quota),
			}

		except httpx.TimeoutException:
			return {
				'success': False,
				'error': '获取用户信息失败：请求超时',
			}

		except httpx.RequestError:
			return {
				'success': False,
				'error': '获取用户信息失败：网络错误',
			}

		except Exception as e:
			return {
				'success': False,
				'error': f'获取用户信息失败：{str(e)[:50]}...',
			}

	@staticmethod
	def _parse_cookies(cookies_data) -> dict[str, str]:
		"""
		解析 cookies 数据

		Args:
		    cookies_data: cookies 数据（字符串或字典格式）

		Returns:
		    dict[str, str]: cookies 字典
		"""
		# 已经是字典格式
		if isinstance(cookies_data, dict):
			return cookies_data

		# 不是字符串格式
		if not isinstance(cookies_data, str):
			return {}

		# 解析字符串格式的 cookies
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			# cookie 格式不正确
			if '=' not in cookie:
				continue

			key, value = cookie.strip().split('=', 1)
			cookies_dict[key] = value

		return cookies_dict
