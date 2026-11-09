from dataclasses import dataclass


@dataclass
class AccountResult:
	"""单个账号的处理结果"""

	# 账号名称
	name: str

	# 处理状态：success 或 failed
	status: str

	# 当前余额，成功时才有
	quota: float | None = None

	# 已使用余额，成功时才有
	used: float | None = None

	# 余额是否发生变化，None 表示获取余额失败无法判断，False 表示未变化或首次运行
	balance_changed: bool | None = None

	# 错误信息，失败时才有
	error: str | None = None

	# 是否因登录凭据（session）失效导致失败，用于在 summary 中区分凭据问题与业务失败
	auth_failed: bool = False
