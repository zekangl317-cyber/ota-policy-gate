# ota-policy-gate

[English](README.md) | [简体中文](README.zh-CN.md)

面向机器人和车载软件 OTA 发布流程的确定性证据闸门。它将基线与候选版本的供应链、接口、权限和回滚证据放到同一个可审计决策中，帮助 CI 在发布前发现不受控的风险漂移。

## 核心能力

- 精确核对产品发布谱系；
- 分析 SBOM 依赖、许可证和组件身份变化；
- 接收外部签名验证结果并绑定清单元数据；
- 检查接口删除、契约兼容性和授权扩张/收缩；
- 验证回滚测试、工件摘要和证据完整性；
- 支持有期限、有预算、可追踪的风险例外；
- 输出稳定 JSON 与适合评审的 Markdown 报告。

## 快速开始

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m ota_policy_gate evaluate `
  --baseline examples/fixtures/baseline.json `
  --candidate examples/fixtures/candidate-safe.json `
  --policy examples/fixtures/policy.json `
  --as-of 2026-07-23
python -m unittest discover -s tests -v
```

运行时仅使用 Python 3.11+ 标准库，无需网络、GPU、容器、付费接口或硬件。安全样例返回通过，风险样例返回阻断；不同结果具有稳定退出码。

## 工程边界

本项目编排签名验证证据，但不自行验证数字签名，也不替代透明日志、SBOM 生成器或完整安全论证。调用方必须先使用真实签名验证器并提供可信结果。

## 协作

刘泽康负责总体设计与主要实现；史浩轩参与发布链路集成和文档核验。职责说明见 [CONTRIBUTORS.md](CONTRIBUTORS.md)。

采用 [MIT License](LICENSE)。
