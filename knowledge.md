# AMACI on Starknet 知识库

## 1. 核心概念和名词解释

### 1.1 证明系统层级

```
zkSNARK                          zkSTARK
├── Groth16 (BN254 pairing)      ├── Stone (Stark252 + 标准 FRI)
├── PLONK (KZG/IPA)             └── Stwo (Mersenne31 + Circle FRI)
└── ...
```

**Stone 和 Stwo 的关系**：类似 Groth16 和 PLONK 的关系——同属 STARK 大类，但底层数学构造完全不同，proof 格式不兼容，verifier 也不通用。

| | Stone | Stwo |
|---|---|---|
| 域 (Field) | Stark252 (大素数域, p ≈ 2^251) | Mersenne31 (小素数域, p = 2^31 - 1) |
| 多项式承诺 | 标准 FRI | Circle FRI (基于 circle group) |
| 向量化 | 有限 | SIMD 16-lane 32-bit 深度优化 |
| 成熟度 | 2020 年上线，5+ 年生产验证 | 2024 年开源，还在快速迭代 |
| 链上 Verifier | Integrity 已部署 | 还没有链上 verifier |
| 性能 | 基线 | 快 10-100x |
| 适用场景 | 当前生产上链唯一路径 | 本地 PoC + 性能验证 |

**关键点**：Stone 和 Stwo 共享同一个前端语言 Cairo。同一份 Cairo program 代码不需要改，只是后端 prover 不同。

### 1.2 SHARP (Shared Prover)

SHARP 不是一种证明系统，是 StarkWare 运营的**共享 prover 服务/基础设施**。

核心功能：
- 接收多个不同来源的 Cairo program 执行
- 用 Stone 分别 prove 每个 job
- 用递归 proof 把多个 proof 聚合成一个
- 统一提交到链上 verifier

"Shared" 的含义：多个不相关的 Cairo program 共享同一次链上验证的 gas 成本。100 个 job 的 verify gas 被 100 个用户分摊。

SHARP 内部使用 **bootloader** 来聚合多个 child program：
```
bootloader program（SHARP 的聚合壳）
    ├── child 0: 你的 tally_votes program
    ├── child 1: 别人的 program A
    └── child 2: 别人的 program B
```

### 1.3 Atlantic

Atlantic 是 Herodotus 公司提供的 **SHARP API 网关**。

```
用户 → Atlantic API → SHARP 集群 (Stone) → 链上 Integrity
```

Atlantic 的价值：
1. 替你跑 prover（省掉大机器）
2. 替你处理 proof → Integrity 的提交流程（proof 压缩、split、calldata 格式化）
3. 自动把 fact 注册到 Integrity

Atlantic **不是** verify 服务，它是 prove + 代提交服务。

### 1.4 Integrity

Integrity 是部署在 Starknet 上的**共享 STARK verifier 合约**，由 Herodotus + StarkWare 合作开发，经过 zkSecurity 审计。

核心是一个链上 mapping：
```
fact_hash → security_bits
```

`fact_hash = hash(program_hash, public_output_hash)`，唯一标识"某个 Cairo program 在某组输入下产生了某个公开输出"。

**类比**：Integrity 对应 zkSNARK 时代链上的 `verifyProof()` 函数，但有两个关键差异：
1. 异步两阶段（先注册 fact，后查询 fact），而非同步一次调用
2. 一次验证多次复用（fact 注册后任何合约都可以便宜地查询）

### 1.5 各组件关系图

```
┌─────────────────────────────────────────────────────────┐
│  StarkWare                                               │
│  • 开发 Stone prover                                     │
│  • 运营 SHARP 集群                                       │
│  • 开发 Cairo 语言 / Starknet 协议                       │
└─────────────────────────────────────────────────────────┘
                         ↕ 合作
┌─────────────────────────────────────────────────────────┐
│  Herodotus                                               │
│  • 开发 Atlantic（SHARP 的 API 网关）                    │
│  • 开发 Integrity（链上 verifier 合约）                  │
│  • 提供开发者工具和文档                                   │
└─────────────────────────────────────────────────────────┘
```

---

## 2. 易混淆点

### 2.1 Atlantic 不是 verify，是 prove + 代提交

```
错误理解：operator prove → Atlantic verify → 链上记录
正确理解：operator 准备输入 → Atlantic prove + 提交 → Integrity 链上 verify → 链上记录 fact
```

STARK verify 虽然比 Groth16 重，但它仍然是链上 Integrity 合约自己做的事（sublinear，可接受）。真正重到需要外包的是 prove（线性甚至超线性，需要大机器大内存）。

### 2.2 Stwo proof 不能直接上链

当前 `scarb prove` 用的是 Stwo，本地 `scarb verify` 能通过，但这个 proof **不能**提交给 Integrity。Integrity 的 verifier 只认 Stone proof。

所以项目里有 `proofProducer = scarb-stwo-local` 和 `Integrity submission ready: no` 的标记。

### 2.3 Integrity 的异步模式 vs Groth16 的同步模式

**Groth16 时代**：一个 tx 搞定
```
proof + publicInputs → verifyProof() 当场计算 → 同 tx 内继续业务
```

**Integrity 时代**：两阶段
```
阶段 1: prover/Atlantic → 把 proof 提交给 Integrity → Integrity 验证 → fact_hash 写入 registry
阶段 2: wrapper → integrity.is_fact_hash_valid(fact_hash, bits) → 查 mapping → 业务逻辑
```

### 2.4 fact_hash 绑定校验是新增的安全要求

Groth16 时代 publicInputs 直接作为 verify 参数，verifier 内部保证 proof 对应这些 inputs。

Integrity 模式下 wrapper 拿到的只是抽象的 fact_hash，必须**自己重算 fact_hash 确认它绑定的是当前 AMACI 状态**，否则攻击者可以用"另一个 batch 的有效 proof"骗过 wrapper。

### 2.5 Cairo program ≠ Cairo contract

- **Cairo program**：类似 Circom circuit 的角色，表达计算关系，生成可证明执行轨迹
- **Cairo contract**：Starknet 链上合约，读取 proof/fact 验证结果，绑定 AMACI 状态

不是把 Circom 写成 Starknet contract。正确路径是：
1. Circom 电路逻辑 → Cairo program
2. Cairo/STARK prover 对 Cairo program 执行生成 proof
3. proof 提交给 Integrity 形成链上可查询 fact
4. Starknet wrapper contract 检查 fact + 绑定 AMACI 状态

### 2.6 为什么 Stwo 还没有链上 verifier

不是"新版本还没部署"这么简单，而是：
1. Stwo 用了完全不同的数学基础（Mersenne31 + Circle FRI），Stone verifier 代码不能验证 Stwo proof
2. 在 Cairo 合约里实现 Circle FRI verifier 工程量巨大且需要审计
3. Stwo 接口还在快速迭代，proof 格式可能还会变
4. StarkWare 优先让 Starknet 自身 OS proof 切到 Stwo，第三方应用优先级低一档
5. 递归方案（Stwo 验证 Stwo proof）还在设计中，可能比"在 Cairo 合约里写 verifier"更优雅

预计 2026 下半年到 2027 年逐步开放。

---

## 3. Operator 流程对比

### 3.1 之前（Circom/Groth16 on CosmWasm）

```
operator:
    1. 收集 batch 数据
    2. 生成 witness
    3. 本地跑 Groth16 prover → 得到 proof（几分钟，普通机器）
    4. 一个 tx：proof + publicInputs → 链上 verify → 通过 → 业务逻辑
```

特点：同步、一个 tx、operator 全程自主。

### 3.2 走 Atlantic 模式

```
operator:
    1. 收集 batch 数据
    2. 生成 witness / Cairo input
    3. 上传到 Atlantic API
    4. 等待：Atlantic 跑 SHARP → 生成 proof → 自动注册 Integrity fact
    5. 轮询/回调确认 fact 已注册
    6. 一个 tx：wrapper.submit_tally_fact(commitment, hash, factHash)
       → wrapper 查 Integrity → 通过 → 业务逻辑
```

特点：异步、有等待时间（分钟~小时）、operator 不需要大机器。

### 3.3 自建 Stone 模式

```
operator:
    1. 收集 batch 数据
    2. 生成 witness / Cairo input
    3. 本地跑 Stone prover（需要 64-256 GB 机器）
    4. tx1：把 proof 提交到 Integrity 的 register_fact（贵，proof 作为 calldata）
    5. tx2：wrapper.submit_tally_fact(commitment, hash, factHash)
       → wrapper 查 Integrity → 通过 → 业务逻辑
```

特点：完全自主、等待时间短（几个区块）、但需要大机器 + 自付 verify gas。

### 3.4 对 operator 代码的改动

```javascript
// 之前
async function processBatch(batch) {
    const witness = generateWitness(batch);
    const { proof, publicInputs } = await localGroth16Prove(witness);
    await contract.submitProof(proof, publicInputs);
}

// Atlantic 模式
async function processBatch(batch) {
    const witness = generateWitness(batch);
    const cairoInput = prepareCairoInput(witness);
    const jobId = await atlantic.submitJob(cairoInput);
    const factHash = await atlantic.waitForFactRegistered(jobId);  // 轮询/webhook
    await wrapper.submit_tally_fact(newCommitment, inputHash, factHash);
}

// 自建 Stone 模式
async function processBatch(batch) {
    const witness = generateWitness(batch);
    const cairoInput = prepareCairoInput(witness);
    const stoneProof = await localStoneProve(cairoInput);          // 大机器
    const factHash = await integrity.registerFact(stoneProof);     // tx1
    await wrapper.submit_tally_fact(newCommitment, inputHash, factHash); // tx2
}
```

---

## 4. 对 AMACI 系统设计的影响

### 4.1 Finality 节奏变慢

单个 batch 从"分钟级"可能拉到"小时级"（如果走 Atlantic 队列）。影响投票截止时间安排。

### 4.2 operator 必须重写成异步任务模型

上传 → 轮询 fact 状态 → 触发 submit。需要完整的 retry 和 recovery 逻辑。

### 4.3 新增失败场景

- Atlantic 上传失败/超时
- SHARP 拒绝 program（layout/builtin 不匹配）
- Integrity register tx 失败或被 reorg
- fact 注册了但 security_bits 不够
- fact 注册成功但 AMACI 状态已被另一个 batch 更新（需要重新 prove）

### 4.4 fact 提交可以解耦 operator 身份

fact 一旦在 Integrity 注册，任何人都可以调用 `submit_tally_fact`。可以拆成：
- operator：只负责跑 prover 和上传
- keeper bot：监听 fact 注册后自动提交 wrapper tx

### 4.5 流水线优化

```
Batch N:   prove → upload → wait → submit
Batch N+1:        prove → upload → wait → submit
```

不同 batch 错开，整体 throughput 提高，但单 batch 延迟不变。

---

## 5. 可选方案对比

### 方案 A：自建 Stone + 自己调 Integrity

**做法**：自己跑 `cpu_air_prover`，用 `proof_serializer` 生成 calldata，直接调 Integrity 的 register_fact。

| 维度 | 评估 |
|------|------|
| 自主性 | 最高，不依赖第三方 |
| 机器成本 | 高（64-256 GB RAM） |
| 延迟 | 低（prove 时间 + 几个区块） |
| 运维 | 重（prover 镜像、layout 兼容、升级跟进） |
| 链上 gas | 高（自己付全部 verify gas） |
| 适用 | 追求最低延迟和最高自主性 |

### 方案 B：Atlantic / SHARP（推荐主线）

**做法**：把 Cairo input 上传到 Atlantic，它走 SHARP 跑 prover，自动注册 Integrity fact。

| 维度 | 评估 |
|------|------|
| 自主性 | 中等，依赖 Atlantic 服务 |
| 机器成本 | 低（operator 只跑 witness 生成） |
| 延迟 | 中等（分钟~小时，受队列影响） |
| 运维 | 轻（不用管 prover） |
| 链上 gas | 低（SHARP 聚合分摊 verify gas） |
| 适用 | 测试网部署 + 早期主网，最快 path-to-production |

**为什么特别贴合当前实现**：wrapper 已经写好了 bootloaded fact 模式（`bootloader_program_hash`、`BOOTLOADER_TASKS`），这正是 SHARP 输出的格式。

### 方案 C：Stwo native（未来）

**做法**：等 Starknet 协议把 Stwo verifier 部署为共享合约或原生支持。

| 维度 | 评估 |
|------|------|
| 自主性 | 高 |
| 机器成本 | 低（Stwo 比 Stone 快 10-100x） |
| 延迟 | 最低（可能回到同步模式） |
| 运维 | 轻 |
| 链上 gas | 可能最低 |
| 适用 | 2026 下半年~2027，作为长期演进方向跟踪 |

### 推荐策略

```
主线：方案 B（Atlantic + Integrity）
保留：方案 A（自建 Stone）作为 fallback，避免 vendor lock-in
跟踪：方案 C（Stwo native），等成熟后切换
```

---

## 6. 当前项目状态快照（2026-05-14）

### 已完成

- 4 大电路 Cairo program 迁移（TallyVotes / AddNewKey / ProcessMessages / ProcessDeactivateMessages）
- 25+ 个 executable target（含 split 子电路）
- 51 个 proof-run 全部 `localProofReady: true`（Stwo 本地验证通过）
- JS reference model + 115 tests (109 pass, 6 skipped)
- tally wrapper 合约完整实现（plain + bootloaded fact 模式）
- MockIntegrity + 完整负例测试（unregistered / insufficient bits / mismatch / stale replay）
- Stone/Integrity CLI 工具链装齐
- tally Stone AIR 能生成（trace 1.5 GiB / memory 747 MiB）

### 卡点

- Stone prover `cpu_air_prover` 在 `recursive` layout 等待高性能机器复跑
- 真实 Stone proof JSON 还没产出
- `proof_serializer` 还没生成真实 Integrity calldata

### 未完成

- Integrity 真实合约接入（当前用 mock）
- Starknet Sepolia 部署
- 链上 fee 实测
- AddNewKey / PM split / PDM split 的 wrapper 合约
- 真实 operator fixture 对照（除 tally 外）
- 生产参数 9-4-3-125

---

## 7. 近期执行计划

### 第一周：打通 Stone proof

1. 高性能机器上用 `recursive` layout 重新生成 tally Stone AIR
2. 跑 `cpu_air_prover` 确认能否产出 Stone proof JSON
3. 跑 `cpu_air_verifier` 本地验证 Stone proof
4. 用 `proof_serializer` 生成 Integrity calldata

### 第二周：Atlantic 接入验证

1. 申请 Atlantic testnet access / mainnet credits
2. 把 tally input 跑一次 Atlantic
3. 拿到 SHARP 出的 fact_hash
4. 验证它和 wrapper 里 `get_expected_bootloaded_fact_hash` 的算法完全一致（关键 sanity check）

### 第三周：Sepolia 部署

1. Pin 真实 `integrity` Cairo 依赖
2. 替换 MockIntegrity 为真实合约地址
3. 部署 wrapper 到 Starknet Sepolia
4. 跑通 `submit_tally_fact` 端到端
5. 记录第一份链上 fee 数据

### 后续

- AddNewKey / PM split / PDM split 的 wrapper 实现
- 真实 operator fixture 对照
- 生产参数 9-4-3-125 评估
- Stwo native 路径跟踪

---

## 8. Wrapper 合约设计要点

### 8.1 当前 tally wrapper 已实现的安全检查

1. **fact_hash 绑定校验**：重算 `plain_fact_hash` 或 `bootloaded_fact_hash`，确保 fact 绑定到当前 AMACI 状态
2. **Integrity 查询**：`is_fact_hash_valid_with_security(fact_hash, min_security_bits)`
3. **stale replay 防护**：提交后 `current_tally_commitment` 更新，旧 fact 自动失效
4. **双模式支持**：`bootloader_program_hash == 0` 走 plain，非零走 bootloaded（SHARP）

### 8.2 split proof wrapper 的额外复杂度（待实现）

对于 ProcessMessages / ProcessDeactivateMessages 的 split proof，wrapper 需要验证多个 fact 之间的关系：
- boundary fact
- coord-key fact
- 每条 message 的 ECDH / signature / decrypt / core-step facts
- message hash chain 连续性
- state root 连续性
- deactivate index 连续性

如果任何链接检查漏掉，可能出现"单个 proof 都有效，但组合起来不是同一批 AMACI 状态"的安全问题。

### 8.3 注意事项

- `processed_user_count += 5` 硬编码了 batch size，后续需要参数化
- `tally_program_hash` 在 constructor 接收且不可改，program 升级需要重新部署 wrapper
- `stone_tally_votes.cairo` 的 public output 序列化必须和 wrapper 的 `public_output_hash` 完全一致

---

## 9. 成本观察

### 9.1 Prover 侧（已有数据）

| 电路 | Prover | 耗时 | 峰值内存 | Proof 大小 |
|------|--------|------|---------|-----------|
| ProcessDeactivateMessages(2,5) deep split | Stwo | 15:13 | 60.5 GiB | ~14 MiB/proof |
| TallyVotes(2,1,1) | Stwo | 待汇总 | 待汇总 | ~14 MiB |
| Tally Stone AIR | cairo1-run | — | — | trace 1.5 GiB, memory 747 MiB |

### 9.2 链上侧（待实测）

| 成本项 | 说明 |
|--------|------|
| Integrity proof submission | proof calldata 上链 + verify 计算 |
| FactRegistry fact 记录 | storage write |
| Wrapper calldata | submit_tally_fact 参数 |
| Split facts 读取校验 | 多个 fact 的 Integrity 查询 |
| AMACI storage write | state commitment / tally commitment 更新 |

### 9.3 生产参数风险

小参数 (2,1,1) / (2,5) 已经需要 60 GiB。生产参数 9-4-3-125 不能直接按当前方式放大，需要：
- 更细拆分
- 递归聚合
- 新的 batching 策略
- 甚至调整 AMACI 协议参数
