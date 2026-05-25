# AMACI on Starknet — Milestone 2: E2E Round Verification Complete

> 2026-05-18 | DoraFactory MACI Team

---

## 1. 这个 Milestone 主要是验证在starknet上运行amaci协议的可行性

完成AMACI 协议在 Starknet 上的**完整投票/计票 E2E 闭环验证**：

```
部署 Round 合约
  → 注册新 key (add-new-key)
  → 处理 5 条加密投票消息 (processMessage, 拆成 22 个 component proofs)
  → 计票 (tally)
  → 链上状态更新确认
```

所有 24 个 proof 通过 Atlantic/SHARP 生成并在 Starknet Sepolia 链上验证注册，29 笔 wrapper 交易全部成功，最终链上状态与本地计算完全一致。

---

## 2. 系统架构总览

### 2.1 从 Groth16/CosmWasm 到 STARK/Starknet 的迁移

```
┌─────────────────────────────────────────────────────────────────┐
│  旧架构 (Circom + Groth16 + CosmWasm)                            │
│                                                                   │
│  Operator → Circom witness → Groth16 prove (本地) → 1 tx 上链验证  │
│  特点: 同步、单 tx、operator 自主                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓ 迁移
┌─────────────────────────────────────────────────────────────────┐
│  新架构 (Cairo + STARK + Starknet)                                │
│                                                                   │
│  Operator → Cairo input → Atlantic (SHARP prove)                  │
│           → Integrity 链上注册 fact                                │
│           → Wrapper 合约查询 fact + 更新状态                       │
│  特点: 异步两阶段、proof 生成外包、gas 分摊                        │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 关键组件关系

```
┌──────────────────────────────────────────────────────────────────────┐
│                         AMACI on Starknet 架构                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐     ┌──────────────┐     ┌───────────────────┐    │
│  │  Operator    │────▶│  Atlantic    │────▶│  SHARP (Stone)    │    │
│  │  (JS/TS)    │     │  (API 网关)   │     │  (共享 Prover)    │    │
│  └─────────────┘     └──────────────┘     └───────────────────┘    │
│        │                                           │                 │
│        │ 准备 Cairo input                          │ 生成 proof      │
│        │                                           ▼                 │
│        │              ┌──────────────────────────────────────┐      │
│        │              │  Integrity (链上 Verifier 合约)        │      │
│        │              │  fact_hash = hash(program, output)    │      │
│        │              │  fact_hash → security_bits mapping    │      │
│        │              └──────────────────────────────────────┘      │
│        │                                           │                 │
│        │                                           │ fact 已注册     │
│        ▼                                           ▼                 │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  MockAmaciRound (Wrapper 合约, Starknet Sepolia)             │    │
│  │  • 查询 Integrity fact 是否有效                               │    │
│  │  • 验证 program hash + public output 绑定当前 AMACI 状态     │    │
│  │  • 更新 state/tally/deactivate commitment                    │    │
│  │  • 防重放: commitment 更新后旧 fact 自动失效                  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.3 为什么用 Atlantic 而不是自建 Prover

| 维度 | 自建 Stone | Atlantic (当前选择) |
|------|-----------|-------------------|
| 机器需求 | 64-256 GB RAM | 无 (外包) |
| verify gas | 自付全部 | SHARP 聚合分摊 |
| 运维 | 重 | 轻 |
| 延迟 | 低 (几个区块) | 中 (分钟~小时) |
| 适用阶段 | 追求最低延迟 | 测试网 + 早期主网 |

---

## 3. 本轮 E2E Round 业务数据

### 3.1 Round 参数

| 参数 | 值 |
|------|---:|
| Round / Poll ID | 77 |
| 注册上限 (numSignUps) | 20 |
| Vote option 数量 | 5 |
| State leaf 数量 | 5 |
| Message batch 数量 | 1 |
| 每 batch 投票消息数 | 5 |
| 加密消息宽度 | 10 felts |

### 3.2 业务流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    完整投票/计票 Round 流程                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ① Deploy Round                                                  │
│     initial_state = 0x1e71...5e5                                 │
│     initial_tally = 0x0                                          │
│                         │                                        │
│                         ▼                                        │
│  ② Add New Key (1 proof)                                         │
│     注册新投票 key, 绑定 nullifier 防重复                         │
│     keysAdded: 0 → 1                                             │
│                         │                                        │
│                         ▼                                        │
│  ③ Process Messages (22 component proofs)                        │
│     解密 5 条投票消息, 验证签名, 执行状态转移                     │
│     state: 0x1e71...5e5 → 0x6870...775                           │
│                         │                                        │
│                         ▼                                        │
│  ④ Tally (1 proof)                                               │
│     汇总投票结果: [16, 21, 26, 31, 36]                           │
│     tally: 0x0 → 0x43ad...8cc                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 投票数据

5 个用户分别对 5 个选项投票，权重矩阵：

```
         Option0  Option1  Option2  Option3  Option4
User 0:    2        2        3        4        5
User 1:    2        4        4        5        6
User 2:    3        4        6        6        7
User 3:    4        5        6        8        8
User 4:    5        6        7        8       10
─────────────────────────────────────────────────────
合计:     16       21       26       31       36
```

最终 tally 结果 `[16, 21, 26, 31, 36]` 被约束进 `newTallyCommitment`，链上只存 commitment（隐私保护），明文结果可由 operator 公开。

---

## 4. ProcessMessage 拆分模型

### 4.1 为什么要拆分

单个 processMessage 电路太大（生产参数下内存需求 60+ GiB），必须拆成小电路分别证明：

```
┌─────────────────────────────────────────────────────────────────┐
│            processMessage 拆分为 6 类 component proof             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐                                             │
│  │ coord-key (×1)  │  约束协调者 key / batch 级公共参数           │
│  └────────┬────────┘                                             │
│           │                                                      │
│           ▼                                                      │
│  ┌─────────────────┐  ┌─────────────────┐                       │
│  │  ecdh (×N)      │  │  decrypt (×N)   │  每条消息的            │
│  │  共享密钥检查    │  │  解密检查        │  密码学验证            │
│  └────────┬────────┘  └────────┬────────┘                       │
│           │                    │                                  │
│           ▼                    ▼                                  │
│  ┌─────────────────┐  ┌─────────────────┐                       │
│  │ signature (×N)  │  │ step-core (×N)  │  每条消息的            │
│  │  签名验证        │  │  状态转移核心    │  业务逻辑验证          │
│  └────────┬────────┘  └────────┬────────┘                       │
│           │                    │                                  │
│           ▼                    ▼                                  │
│  ┌─────────────────────────────────────────┐                     │
│  │         boundary (×1)                    │                     │
│  │  约束整个 batch 的起止状态承接            │                     │
│  └─────────────────────────────────────────┘                     │
│                                                                  │
│  总 proof 数 = 2 + 4N  (N = 消息数)                              │
│  本轮 N=5:  2 + 4×5 = 22 proofs                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 本轮实际 proof 分布

| Component | 数量 | 角色 |
|-----------|-----:|------|
| coord-key | 1 | batch 级协调者参数 |
| ecdh | 5 | ECDH 共享密钥 |
| decrypt | 5 | 消息解密 |
| signature | 5 | 命令签名验证 |
| step-core | 5 | 状态转移核心逻辑 |
| boundary | 1 | batch 起止状态约束 |
| **合计** | **22** | |

---

## 5. 验证链路 (Trust Chain)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        端到端验证链路                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ① 本地 Fixture 数据                                                 │
│     JS evaluator 用 Starknet Poseidon 计算 commitment                │
│                    │                                                  │
│                    ▼                                                  │
│  ② Cairo Native Program                                              │
│     重新计算并 assert 同样的 commitment (不信任 JS)                    │
│                    │                                                  │
│                    ▼                                                  │
│  ③ Atlantic / SHARP                                                   │
│     Stone prover 生成 STARK proof                                     │
│     proof 提交到 Integrity 链上验证                                   │
│     fact_hash 注册到 FactRegistry                                     │
│                    │                                                  │
│                    ▼                                                  │
│  ④ MockAmaciRound (链上 Wrapper)                                      │
│     查询 Integrity: fact 是否有效?                                    │
│     验证: program hash 在 allowlist 中?                               │
│     验证: public output 绑定当前 round 状态?                          │
│     通过 → 更新 state/tally commitment                                │
│                    │                                                  │
│                    ▼                                                  │
│  ⑤ 链上 Getter 返回值 = 本地 Fixture 预期值  ✓                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

关键 commitment 公式：

```
stateCommitment     = Poseidon(stateRoot, stateSalt)
tallyCommitment     = Poseidon(resultsRoot, resultsRootSalt)
deactivateCommitment = Poseidon(activeStateRoot, deactivateRoot)
```

---

## 6. Fact 注册模式

Atlantic 注册的不是直接绑定 native circuit output 的 fact，而是 **metadata-level bootloaded fact**：

```
┌─────────────────────────────────────────────────────────────────┐
│                    Fact 注册层级结构                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SHARP Bootloader                                                │
│  ├── Metadata Program (Atlantic 的包装层)                        │
│  │   └── metadata output 包含:                                   │
│  │       • child program hash (= native circuit hash)            │
│  │       • native circuit public output                          │
│  │       • security bits / verifier config                       │
│  └── 其他 jobs (SHARP 聚合的其他用户 program)                    │
│                                                                  │
│  链上注册的 fact:                                                 │
│    fact_hash = hash(metadata_program_hash, metadata_output_hash) │
│                                                                  │
│  Wrapper 验证逻辑:                                               │
│    1. 确认 fact_hash 在 Integrity 已注册                         │
│    2. 从 metadata output 提取 child program hash                 │
│    3. 确认 child program hash 在 allowlist                       │
│    4. 从 metadata output 提取 native public output               │
│    5. 验证 public output 中的 commitment 绑定当前状态            │
│                                                                  │
│  模式标识: bootloaded:metadata-output:metadata-program:sharp     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. 成本数据 (核心)

### 7.1 成本总览

本轮完整 E2E round (5 条消息, 24 个 proof) 的实测成本：

```
┌─────────────────────────────────────────────────────────────────┐
│                      成本结构分层                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Layer 1: Atlantic Credit (Proof 生成 + 代提交)          │    │
│  │  7,200 credits = $72.00                                  │    │
│  │  (24 queries × 300 credits/query)                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Layer 2: Proof Verification Gas (Atlantic 代付)         │    │
│  │  95.117 STRK                                             │    │
│  │  (24 queries × ~215 笔 verification tx)                  │    │
│  │  ⚠️ 这是当前最大成本项                                   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Layer 3: AMACI Wrapper 业务交易 (我们自付)              │    │
│  │  0.591 STRK (24 笔 fact consumption tx)                  │    │
│  │  0.060 STRK (5 笔 allowlist tx)                          │    │
│  │  0.060 STRK (1 笔 deploy tx)                             │    │
│  │  合计: 0.711 STRK                                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 成本占比分析

| 成本层 | 金额 | 占比 | 说明 |
|--------|------|-----:|------|
| Atlantic proof verification gas | 95.117 STRK | 99.3% | Atlantic 代付，包含在 credit 费用中 |
| AMACI wrapper 业务交易 | 0.711 STRK | 0.7% | 我们账户实际支出 |
| **链上总计** | **95.828 STRK** | 100% | |
| Atlantic credits (链下) | $72.00 | — | 覆盖 prove + verification gas |

**核心结论**: 成本绝大部分在 proof verification（链上验证 STARK proof 的 gas），我们自己的业务交易成本极低。Atlantic credit 模式下，$72 覆盖了全部 prove + verify 成本。

### 7.3 按业务阶段拆分

| 阶段 | Proof 数 | Wrapper Gas | Verification Gas | Atlantic Credits |
|------|--------:|------------:|----------------:|----------------:|
| Add New Key | 1 | 0.038 STRK | 3.857 STRK | 300 ($3) |
| ProcessMessage | 22 | 0.521 STRK | 87.442 STRK | 6,600 ($66) |
| Tally | 1 | 0.031 STRK | 3.819 STRK | 300 ($3) |
| **合计** | **24** | **0.591 STRK** | **95.117 STRK** | **7,200 ($72)** |

### 7.4 ProcessMessage 内部成本拆分

| Component | 数量 | Wrapper Gas | 单笔 Verification Gas |
|-----------|-----:|------------:|---------------------:|
| coord-key | 1 | 0.017 STRK | ~3.82 STRK |
| ecdh | 5 | 0.088 STRK | ~3.89 STRK/笔 |
| decrypt | 5 | 0.090 STRK | ~3.86 STRK/笔 |
| signature | 5 | 0.095 STRK | ~3.88 STRK/笔 |
| step-core | 5 | 0.204 STRK | ~4.41 STRK/笔 |
| boundary | 1 | 0.028 STRK | ~3.47 STRK |

**观察**: step-core 的 verification gas 明显高于其他 component（~4.4 vs ~3.8 STRK），因为它包含状态转移核心逻辑，proof 更大。

### 7.5 Atlantic Credit 两种口径对比

| 口径 | 总 Credits | 总 USD | 来源 |
|------|----------:|-------:|------|
| 实际 API quote (保守) | 7,200 | $72.00 | Atlantic x402 支付请求 |
| 官方 pricing 公式 (testnet) | 1,704 | $17.04 | 文档: S=70 + trace=1 |
| 官方 pricing 公式 (mainnet) | 2,304 | $23.04 | 文档: S=70 + trace=1 + verify=25 |

**建议**: 对外沟通用 $72 (实际 quote)，内部优化目标参考 $23 (理论值)。差异原因待与 Herodotus 确认。

---

## 8. 链上验证结果

### 8.1 最终链上状态

Round 合约地址: [`0x05b2...6262`](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262)

| Getter | 链上值 | 含义 |
|--------|--------|------|
| `get_state_commitment` | `0x6870...775` | processMessage 后的最终状态 |
| `get_deactivate_commitment` | `0x2838...e94` | 未变 (本轮无 deactivate) |
| `get_tally_commitment` | `0x43ad...8cc` | tally 结果 commitment |
| `get_keys_added` | 1 | 注册了 1 个 key |
| `get_message_batches_processed` | 1 | 处理了 1 个 batch |
| `get_total_facts_accepted` | 24 | 消费了 24 个 proof facts |
| `get_tally_submitted` | true | 计票完成 |

### 8.2 关键交易

| 操作 | 交易 |
|------|------|
| Deploy | [`0x0757...3a5a`](https://sepolia.voyager.online/tx/0x0757cc62acbf464d8c94b4b1a3d78d8174ed4e1bca61f446726d889a51533a5a) |
| Add Key | [`0x07ad...9170`](https://sepolia.voyager.online/tx/0x07add36b0c8df227b5740ef238e2a6761709919c435810f562a0162905f99170) |
| Process Messages Boundary | [`0x0125...5b9f`](https://sepolia.voyager.online/tx/0x01253237213d436d1f9d0312896e79cccb6c03605652e38e89309ad796095b9f) |
| Tally | [`0x0097...8049`](https://sepolia.voyager.online/tx/0x0097d44d00d4124454df39b5108924e8bbb873236879fe5df1bc3d16726a8049) |

---

## 9. Native Circuit 覆盖度

| 电路族 | Native Circuits | Atlantic 验证 | Wrapper 消费 |
|--------|----------------|:------------:|:------------:|
| Add Key | `add-new-key-native` | ✅ | ✅ |
| ProcessMessage | coord-key, ecdh, decrypt, signature, step-core, boundary | ✅ | ✅ |
| ProcessDeactivate | coord-key, ecdh, decrypt, signature, step-core, boundary | ✅ | ✅ |
| Tally | `tally-native` | ✅ | ✅ |

> ProcessDeactivate 的 Atlantic 路径和 wrapper 消费路径已补齐，但不在本轮投票/计票 round 的成本统计中。

---

## 10. 与旧架构的关键差异

| 维度 | 旧 (Groth16/CosmWasm) | 新 (STARK/Starknet) |
|------|----------------------|---------------------|
| 证明系统 | Groth16 (trusted setup) | STARK (transparent, no setup) |
| 验证模式 | 同步: 1 tx 内 verify + 业务 | 异步: fact 注册 → 查询消费 |
| Prover 需求 | 普通机器, 几分钟 | 外包给 Atlantic/SHARP |
| 链上 gas | 低 (Groth16 verify 便宜) | 高 (STARK verify 贵, 但 SHARP 分摊) |
| 安全性 | 依赖 trusted setup | 无 trusted setup, 量子安全 |
| Fact 复用 | 不支持 | 一次验证, 多次查询 |
| 拆分 proof | 不需要 | 必须 (大电路拆成 component) |

---

## 11. 成本优化方向

当前 `2 + 4N` 模型意味着消息数线性增长时，proof 数和成本也线性增长：

```
N=5:   24 proofs,  $72,   95 STRK verification
N=25:  ~104 proofs, ~$312, ~412 STRK verification  (估算)
N=125: ~504 proofs, ~$1512, ~2000 STRK verification (估算)
```

优化路径：

| 方案 | 效果 | 时间线 |
|------|------|--------|
| Recursive proof aggregation | 多个 component proof 聚合成 1 个 | 近期可做 |
| Batch 内 proof 合并 | 减少 per-message proof 数 | 需要电路重构 |
| Stwo native 上链 | prove 快 10-100x, 可能回到同步模式 | 2026H2-2027 |
| SHARP 更好的分摊 | verification gas 被更多用户分摊 | 取决于 SHARP 负载 |

---

## 12. 生产化 Remaining Work

1. **MockAmaciRound → 生产合约**: 把流程约束迁移成正式 AMACI 合约接口
2. **Program hash 管理**: 确定 allowlist / 升级策略
3. **状态机接入**: add-key / processMessage / processDeactivate / tally 接入真实 round 生命周期
4. **Deactivate round**: 单独的 deactivate 成本流程
5. **Aggregate proof**: 减少 `2 + 4N` 带来的 query 数和 verification 成本
6. **生产参数 9-4-3-125**: 评估大参数下的可行性

---

## 13. 总结

| 指标 | 结果 |
|------|------|
| E2E 闭环 | ✅ 完成 |
| Atlantic queries | 24/24 DONE |
| Wrapper 交易 | 29/29 成功 |
| 链上状态一致性 | ✅ 通过 |
| 单轮总成本 (Atlantic credits) | $72 |
| 单轮 wrapper 自付 gas | 0.711 STRK |
| 单轮 verification gas (Atlantic 代付) | 95.117 STRK |
| 网络 | Starknet Sepolia |
| 测试日期 | 2026-05-18 |

这是 AMACI 协议从 Circom/Groth16/CosmWasm 迁移到 Cairo/STARK/Starknet 后的**第一次完整投票/计票 E2E 链上验证**。证明了整条路径的可行性，并建立了成本基线用于后续优化。
