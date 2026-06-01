# AMACI on Starknet：基于 zkSTARK 的匿名投票协议

## 概述

本文档描述 AMACI（Anonymous Minimal Anti-Collusion Infrastructure，匿名最小化反串谋基础设施）在 Starknet 上的架构与实现。系统使用 Cairo 程序生成 zkSTARK 证明，实现链上隐私投票：投票内容不会以明文出现在链上，投票处理和计票结果的正确性由零知识证明保证，并且无需可信设置（Trusted Setup）。

需要先明确两个边界：

- **隐私边界**：AMACI/MACI 模型中的 Operator 负责解密和处理加密消息，因此 Operator 可以看到投票明文；隐私保护的对象主要是链上和公众观察者。Operator 不能任意篡改状态转换或计票结果，因为每个阶段都必须通过 Cairo 程序约束和 STARK proof 验证。
- **E2E 测试边界**：本文记录的是协议级和合约级 E2E 验证，使用 JS fixture 确定性生成用户密钥、消息和 witness，再提交给 Atlantic 生成并验证 proof。这不是最终产品的前端交互流程，也不是生产环境的唯一部署方式。

---

## 术语表

在阅读本文档前，以下是会反复出现的核心术语：

| 术语 | 解释 |
| --- | --- |
| **felt252** | Cairo 语言的基本数据类型，全称 field element（域元素）。它是 STARK 素数域（P = 2^251 + 17×2^192 + 1）中的一个元素，取值范围 0 到 P-1。所有 Cairo 程序的输入输出最终都表示为 felt252 数组。 |
| **Cairo** | StarkWare 开发的编程语言，专为生成 STARK 证明设计。程序中的每一步执行都会被记录为"执行轨迹"，证明器基于此轨迹生成零知识证明。 |
| **Sierra** | Cairo 程序的编译中间产物（Safe Intermediate Representation）。`.cairo` 源码通过 `scarb build` 编译为 Sierra JSON 文件，这个文件就是提交给证明器的"电路"。 |
| **Witness（见证）** | 证明者（Operator）拥有的私有数据，如协调者私钥、解密后的投票命令、Merkle 路径等。这些数据不会出现在公开输出中，但证明保证了它们的正确性。 |
| **Commitment（承诺）** | 对某个值的哈希绑定，形如 `H(value, salt)`。链上只存储 commitment，不存储原始值。任何人无法从 commitment 反推原始值，但可以验证"某个值是否对应这个 commitment"。 |
| **Fact** | 在 Starknet 的 Integrity FactRegistry 中注册的一条记录，表示"某个 Cairo 程序在某组输入上正确执行并产生了某个公开输出"。链上合约通过查询 fact 来验证证明。 |
| **Poseidon** | 一种专为有限域算术设计的哈希函数。在 STARK 证明中效率极高（因为其内部结构全部由域上的加法和乘法组成），本系统中所有 Merkle 树、commitment、inputHash 均使用 Poseidon。 |
| **Operator（协调者）** | 运行 AMACI 轮次的实体。负责收集加密消息、解密处理、生成证明并提交链上状态更新。Operator 可以看到投票明文，但无法篡改结果（受 Cairo 程序和 STARK proof 约束）。 |
| **Atlantic** | Herodotus 提供的证明即服务（Proving-as-a-Service）平台。Operator 提交 programFile + inputFile，Atlantic 负责执行程序、生成 STARK 证明、在 Starknet 上验证并注册 fact。当前 E2E 使用 Atlantic 跑通端到端证明和 fact 注册流程；后续如果自托管 prover，Operator 可以在本地生成 Stone proof，再自行提交 Integrity 验证交易。使用 Atlantic 时，inputFile/witness 会进入 Atlantic 的执行环境，因此它是当前测试架构中的第三方执行边界。 |

### Cairo 程序的编译与执行

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  编译阶段（一次性，电路确定后不再变化）                                        │
│                                                                             │
│  ┌────────────────┐         ┌─────────────────────────────────────────┐    │
│  │  .cairo 源码   │──scarb──→│  Sierra JSON (programFile)             │    │
│  │                │  build   │                                         │    │
│  │ 定义验证逻辑:  │         │  编译后的程序表示，类似 Java .class       │    │
│  │ • assert 约束  │         │  或 WebAssembly。包含所有约束逻辑。       │    │
│  │ • 哈希计算     │         │  每组电路参数编译一次，之后固定不变。      │    │
│  │ • Merkle 验证  │         │                                         │    │
│  │ • 状态转换     │         │  program_hash = H(Sierra JSON)          │    │
│  └────────────────┘         │  → 链上合约用此哈希验证电路身份           │    │
│                              └─────────────────────────────────────────┘    │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  执行与证明阶段（每轮投票不同）                                               │
│                                                                             │
│  ┌─────────────────────────────────────────┐                               │
│  │  inputFile (felt252 数组)               │                               │
│  │                                         │                               │
│  │  Operator 准备的业务数据:               │                               │
│  │  • coordPrivKey (协调者私钥)            │                               │
│  │  • 加密消息 msgs[]                      │                               │
│  │  • Merkle 路径                          │                               │
│  │  • 状态叶子                             │                               │
│  │  • ...                                  │                               │
│  │                                         │                               │
│  │  按 Cairo struct 字段顺序序列化为        │                               │
│  │  一维 felt252 数组                      │                               │
│  └──────────────────┬──────────────────────┘                               │
│                     │                                                       │
│                     ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Sierra JSON + inputFile ──→ Cairo VM 执行 ──→ STARK Proof          │   │
│  │                                                                     │   │
│  │  执行轨迹 (trace): 程序每一步的寄存器状态                             │   │
│  │  公开输出 (public output): 程序的返回值 (commitments, inputHash)     │   │
│  │  STARK 证明: "存在合法输入使程序正确执行并产出该公开输出"              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 第一部分：amaci Cairo 电路架构

### 什么是 Cairo 电路

在本系统中，"电路"指的是可被证明执行的 Cairo 程序。这个叫法是为了和传统 ZK 系统中的 circuit 概念对齐；实际实现上，它们是 Cairo 源码和编译后的 Sierra JSON。每个程序接收私有见证数据（witness）作为输入，执行密码学验证逻辑，并输出一组公开承诺值（commitment）。程序通过 `scarb build` 编译为 Sierra JSON，STARK 证明器基于程序的执行轨迹生成证明。

```text
┌──────────────────────────────────────────────────────────────┐
│                     Cairo 程序（电路）                         │
│                                                              │
│  输入：公开字段 + 私有见证（felt252 数组）                      │
│  逻辑：密码学验证（Poseidon 哈希、Merkle 路径、                │
│        签名校验、状态转换）                                    │
│  输出：规范化公开输出（Array<felt252>）                         │
│                                                              │
│  STARK 证明保证：                                             │
│  "存在一组合法的见证数据，使得程序正确执行并产生了该公开输出。"    │
└──────────────────────────────────────────────────────────────┘
```

### 电路参数（2-1-1-3）

当前实现使用固定参数集：

| 参数 | 值 | 含义 |
| --- | ---: | --- |
| stateTreeDepth | 2 | 5 叉 Merkle 树，25 个状态叶子 |
| intStateTreeDepth | 1 | 每个 tally 批次处理 5 个叶子 |
| voteOptionTreeDepth | 1 | 每个投票者有 5 个投票选项 |
| messageBatchSize | 3 | 每个证明批次处理 3 条加密消息 |

### 电路族

系统由四个电路族组成，分别负责 AMACI 轮次的一个阶段：

```text
┌─────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐   ┌─────────────┐
│   添加新密钥     │   │     处理停用消息      │   │     处理投票消息      │   │    计票     │
│  (Add New Key)  │   │(Process Deactivate)  │   │ (Process Messages)   │   │  (Tally)   │
│                 │   │                      │   │                      │   │             │
│  证明密钥注册    │   │  证明 3 条停用请求    │   │  证明 3 条投票命令    │   │  证明票数   │
│  操作合法       │   │  被正确处理并更新状态  │   │  被正确处理并更新状态  │   │  计算正确   │
└─────────────────┘   └──────────────────────┘   └──────────────────────┘   └─────────────┘
```

#### 1. 添加新密钥（`add_new_key_native`）

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Add New Key (单个电路，一次证明)                          │
│                                                                             │
│  输入 (witness):                                                            │
│    coordPubKey          协调者公钥                                           │
│    oldPrivateKey        旧私钥                                              │
│    newPubKey            新公钥                                              │
│    pollId              投票轮次 ID                                           │
│    c1, c2              停用叶子中的 ElGamal 密文                             │
│    d1, d2              重随机化后的密文                                      │
│    sharedKey           ECDH 共享密钥                                        │
│    deactivateIndex     停用树中的叶子索引                                    │
│    deactivateLeafPath[0..3]  4 层 Merkle 路径                               │
│                                                                             │
│  验证步骤:                                                                   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 1. 哈希绑定验证                                                      │   │
│  │    • H(coordPubKey) == coordPubKeyHash                               │   │
│  │    • H(newPubKey) == newPubKeyHash                                   │   │
│  │    • H(c1) == c1Hash, H(c2) == c2Hash                               │   │
│  │    • H(sharedKey) == sharedKeyHash                                   │   │
│  │    • H(d1) == d1Hash, H(d2) == d2Hash                               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 2. Nullifier 计算                                                    │   │
│  │    nullifier = Poseidon(domain, oldPrivateKey, pollId)                │   │
│  │    → 防止同一旧密钥重复注册新密钥                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 3. 停用叶子验证                                                      │   │
│  │    deactivateLeaf = Poseidon(domain, c1Hash, c2Hash, sharedKeyHash)  │   │
│  │    → 证明旧密钥确实被停用过（叶子数据正确）                             │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 4. Merkle 包含证明                                                   │   │
│  │    从 deactivateLeaf + path[0..3] 重建树根                            │   │
│  │    assert(重建的根 == deactivateRootHash)                             │   │
│  │    → 证明这个停用叶子确实在停用树中                                    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 5. 重随机化绑定                                                      │   │
│  │    rerandomizeBindingHash =                                          │   │
│  │      Poseidon(domain, coordPubKeyHash, c1Hash, c2Hash, d1Hash, d2Hash)│  │
│  │    → 证明 d1/d2 是 c1/c2 的合法重随机化                               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 6. Input Hash (类似 Boundary 的作用)                                  │   │
│  │    inputHash = Poseidon(domain, deactivateRoot, coordPubKeyHash,     │   │
│  │                nullifier, c1Hash, c2Hash, sharedKeyHash,             │   │
│  │                deactivateLeafHash, d1Hash, d2Hash,                   │   │
│  │                rerandomizeBindingHash, newPubKeyHash, pollId)         │   │
│  │    → 把所有公开字段聚合成一个哈希，供链上合约验证                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  公开输出 (19 个 felt):                                                      │
│    magic, version, circuitId, hashScheme,                                   │
│    stateTreeDepth, deactivateTreeDepth,                                     │
│    deactivateRootHash, coordPubKeyHash, nullifier,                          │
│    c1Hash, c2Hash, sharedKeyHash, deactivateLeafHash,                       │
│    d1Hash, d2Hash, rerandomizeBindingHash,                                  │
│    newPubKeyHash, pollId, inputHash                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 2. 处理停用消息（`process_deactivate_stage_native`）

证明一批 3 条停用消息被正确处理。对每条消息，电路验证：

- **ECDH**：协调者的共享密钥正确派生
- **解密**：加密命令解密后为合法的停用请求
- **签名**：投票者的 EdDSA 签名授权了该停用操作
- **状态转换**：活跃状态树和停用树被正确更新

**公开输出**：当前/新停用承诺、消息哈希链、状态根。


对应文件：

| 文件 | 角色 |
| --- | --- |
| `native_process_deactivate.cairo` | Boundary — 批次级别的承诺和哈希链约束 |
| `native_process_deactivate_components.cairo` | 子组件 — CoordKey / ECDH / Signature / Decrypt |
| `native_process_deactivate_step_core.cairo` | Step Core — 单条停用消息的状态转换 |
| `native_process_deactivate_stage.cairo` | Stage 入口 — 组合所有模块并验证交叉链接 |

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                   Process Deactivate Stage (一次证明)                             │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ CoordKey (1次) — 同 Process Messages                                    │    │
│  └──────────────────────────────────┬──────────────────────────────────────┘    │
│                                     │                                           │
│         ┌───────────────────────────┼───────────────────────────┐               │
│         ▼                           ▼                           ▼               │
│  ┌──────────────┐           ┌──────────────┐           ┌──────────────┐        │
│  │   消息 0     │           │   消息 1     │           │   消息 2     │        │
│  │              │           │              │           │              │        │
│  │ ┌──────────┐│           │ ┌──────────┐│           │ ┌──────────┐│        │
│  │ │Cmd ECDH  ││           │ │Cmd ECDH  ││           │ │Cmd ECDH  ││        │
│  │ │命令解密用 ││           │ │命令解密用 ││           │ │命令解密用 ││        │
│  │ │共享密钥  ││           │ │共享密钥  ││           │ │共享密钥  ││        │
│  │ └────┬─────┘│           │ └────┬─────┘│           │ └────┬─────┘│        │
│  │      │      │           │      │      │           │      │      │        │
│  │ ┌────▼─────┐│           │ ┌────▼─────┐│           │ ┌────▼─────┐│        │
│  │ │Leaf ECDH ││           │ │Leaf ECDH ││           │ │Leaf ECDH ││        │
│  │ │停用叶子用 ││           │ │停用叶子用 ││           │ │停用叶子用 ││        │
│  │ │共享密钥  ││           │ │共享密钥  ││           │ │共享密钥  ││        │
│  │ └────┬─────┘│           │ └────┬─────┘│           │ └────┬─────┘│        │
│  │      │      │           │      │      │           │      │      │        │
│  │ ┌────▼─────┐│           │ ┌────▼─────┐│           │ ┌────▼─────┐│        │
│  │ │Signature ││           │ │Signature ││           │ │Signature ││        │
│  │ │验证停用  ││           │ │验证停用  ││           │ │验证停用  ││        │
│  │ │授权签名  ││           │ │授权签名  ││           │ │授权签名  ││        │
│  │ └────┬─────┘│           │ └────┬─────┘│           │ └────┬─────┘│        │
│  │      │      │           │      │      │           │      │      │        │
│  │ ┌────▼─────┐│           │ ┌────▼─────┐│           │ ┌────▼─────┐│        │
│  │ │Cur Decrypt│           │ │Cur Decrypt│           │ │Cur Decrypt│        │
│  │ │当前活跃  ││           │ │当前活跃  ││           │ │当前活跃  ││        │
│  │ │密文解密  ││           │ │密文解密  ││           │ │密文解密  ││        │
│  │ └────┬─────┘│           │ └────┬─────┘│           │ └────┬─────┘│        │
│  │      │      │           │      │      │           │      │      │        │
│  │ ┌────▼─────┐│           │ ┌────▼─────┐│           │ ┌────▼─────┐│        │
│  │ │New Decrypt│           │ │New Decrypt│           │ │New Decrypt│        │
│  │ │新停用密文 ││           │ │新停用密文 ││           │ │新停用密文 ││        │
│  │ │解密验证  ││           │ │解密验证  ││           │ │解密验证  ││        │
│  │ └────┬─────┘│           │ └────┬─────┘│           │ └────┬─────┘│        │
│  │      │      │           │      │      │           │      │      │        │
│  │ ┌────▼─────┐│           │ ┌────▼─────┐│           │ ┌────▼─────┐│        │
│  │ │Step Core ││           │ │Step Core ││           │ │Step Core ││        │
│  │ │更新active││           │ │更新active││           │ │更新active││        │
│  │ │树+deact树││           │ │树+deact树││           │ │树+deact树││        │
│  │ └──────────┘│           │ └──────────┘│           │ └──────────┘│        │
│  └──────┬───────┘           └──────┬───────┘           └──────┬───────┘        │
│         │                          │                          │                 │
│         └──────────────────────────┼──────────────────────────┘                 │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ Boundary (1次)                                                          │    │
│  │   • currentDeactivateCommitment = H(currentActiveRoot, currentDeactRoot)│    │
│  │   • newDeactivateCommitment = H(newActiveRoot, newDeactRoot)            │    │
│  │   • 消息哈希链完整性                                                     │    │
│  │   • inputHash 正确                                                      │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ 交叉链接验证                                                             │    │
│  │                                                                         │    │
│  │ 状态根链 (active 树 + deactivate 树):                                    │    │
│  │   Core[0].newActiveRoot == Core[1].currentActiveRoot                    │    │
│  │   Core[1].newActiveRoot == Core[2].currentActiveRoot                    │    │
│  │   Core[0].newDeactivateRoot == Core[1].currentDeactivateRoot            │    │
│  │   Core[1].newDeactivateRoot == Core[2].currentDeactivateRoot            │    │
│  │                                                                         │    │
│  │ 消息哈希链:                                                              │    │
│  │   batchStartHash → Core[0].next → Core[1].next → Core[2].next          │    │
│  │                                                    = batchEndHash        │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  最终公开输出:                                                                   │
│    currentDeactivateCommitment, newDeactivateCommitment, newDeactivateRoot,     │
│    batchStartHash, batchEndHash, coordPubKeyHash, currentStateRoot, inputHash   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### 3. 处理投票消息（`process_messages_stage_native`）

证明一批 3 条投票消息被正确处理。对每条消息：

- **ECDH**：投票者与协调者之间的共享密钥派生
- **解密**：消息解密得到合法的投票命令
- **签名**：EdDSA 签名验证
- **状态转换**：投票权重、余额、nonce 更新正确

**公开输出**：当前/新状态承诺、停用承诺、消息哈希链。

对应文件：

| 文件 | 角色 |
| --- | --- |
| `native_process_messages.cairo` | Boundary — 批次级别的承诺和哈希链约束 |
| `native_process_message_components.cairo` | 子组件 — CoordKey / ECDH / Decrypt / Signature |
| `native_process_message_step_core.cairo` | Step Core — 单条消息的完整状态转换 |
| `native_process_messages_stage.cairo` | Stage 入口 — 组合所有模块并验证交叉链接 |

完整流程图：

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Process Messages Stage (一次证明)                              │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ CoordKey (1次)                                                          │    │
│  │ 验证协调者拥有私钥，且私钥/公钥配对                                        │    │
│  │ 输入: coordPrivKey, coordPubKey                                         │    │
│  │ 输出: coordPubKeyHash, coordPrivKeyHash, coordKeyBindingHash            │    │
│  └──────────────────────────────────┬──────────────────────────────────────┘    │
│                                     │ coordPrivKeyHash (共享给所有消息)          │
│         ┌───────────────────────────┼───────────────────────────┐               │
│         ▼                           ▼                           ▼               │
│  ┌─────────────┐            ┌─────────────┐            ┌─────────────┐         │
│  │  消息 0     │            │  消息 1     │            │  消息 2     │         │
│  │             │            │             │            │             │         │
│  │ ┌─────────┐│            │ ┌─────────┐│            │ ┌─────────┐│         │
│  │ │  ECDH   ││            │ │  ECDH   ││            │ │  ECDH   ││         │
│  │ │ 计算共享 ││            │ │ 计算共享 ││            │ │ 计算共享 ││         │
│  │ │ 密钥绑定 ││            │ │ 密钥绑定 ││            │ │ 密钥绑定 ││         │
│  │ └────┬────┘│            │ └────┬────┘│            │ └────┬────┘│         │
│  │      │     │            │      │     │            │      │     │         │
│  │ ┌────▼────┐│            │ ┌────▼────┐│            │ ┌────▼────┐│         │
│  │ │ Decrypt ││            │ │ Decrypt ││            │ │ Decrypt ││         │
│  │ │ 验证活跃 ││            │ │ 验证活跃 ││            │ │ 验证活跃 ││         │
│  │ │ 状态解密 ││            │ │ 状态解密 ││            │ │ 状态解密 ││         │
│  │ └────┬────┘│            │ └────┬────┘│            │ └────┬────┘│         │
│  │      │     │            │      │     │            │      │     │         │
│  │ ┌────▼────┐│            │ ┌────▼────┐│            │ ┌────▼────┐│         │
│  │ │Signature││            │ │Signature││            │ │Signature││         │
│  │ │ 验证投票 ││            │ │ 验证投票 ││            │ │ 验证投票 ││         │
│  │ │ 者签名  ││            │ │ 者签名  ││            │ │ 者签名  ││         │
│  │ └────┬────┘│            │ └────┬────┘│            │ └────┬────┘│         │
│  │      │     │            │      │     │            │      │     │         │
│  │ ┌────▼────┐│            │ ┌────▼────┐│            │ ┌────▼────┐│         │
│  │ │Step Core││            │ │Step Core││            │ │Step Core││         │
│  │ │ 执行状态 ││            │ │ 执行状态 ││            │ │ 执行状态 ││         │
│  │ │ 转换    ││            │ │ 转换    ││            │ │ 转换    ││         │
│  │ └─────────┘│            │ └─────────┘│            │ └─────────┘│         │
│  └──────┬──────┘            └──────┬──────┘            └──────┬──────┘         │
│         │                          │                          │                 │
│         └──────────────────────────┼──────────────────────────┘                 │
│                                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ Boundary (1次)                                                          │    │
│  │ 验证批次级别约束:                                                         │    │
│  │   • currentStateCommitment = H(currentStateRoot, currentStateSalt)      │    │
│  │   • newStateCommitment = H(newStateRoot, newStateSalt)                  │    │
│  │   • deactivateCommitment = H(activeStateRoot, deactivateRoot)           │    │
│  │   • 消息哈希链完整性                                                     │    │
│  │   • inputHash 正确                                                      │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │ 交叉链接验证 (Stage 的核心职责)                                           │    │
│  │                                                                         │    │
│  │ 数据一致性:                                                              │    │
│  │   CoordKey.privKeyHash == ECDH[i].privKeyHash == Core[i].privKeyHash    │    │
│  │   ECDH[i].sharedKeyHash == Core[i].sharedKeyHash                       │    │
│  │   Decrypt[i].c1Hash == Core[i].stateCiphertextC1Hash                   │    │
│  │   Signature[i].commandAuthHash == Core[i].commandAuthHash              │    │
│  │                                                                         │    │
│  │ 消息哈希链:                                                              │    │
│  │   batchStartHash → Core[0].next → Core[1].next → Core[2].next          │    │
│  │                                                    = batchEndHash        │    │
│  │                                                                         │    │
│  │ 状态根链 (消息从后往前处理):                                               │    │
│  │   Boundary.currentStateRoot == Core[2].currentStateRoot                 │    │
│  │   Core[2].newStateRoot == Core[1].currentStateRoot                      │    │
│  │   Core[1].newStateRoot == Core[0].currentStateRoot                      │    │
│  │   Core[0].newStateRoot == Boundary.newStateRoot                         │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  最终公开输出:                                                                   │
│    currentStateCommitment, newStateCommitment, deactivateCommitment,            │
│    batchStartHash, batchEndHash, coordPubKeyHash, inputHash                     │
└─────────────────────────────────────────────────────────────────────────────────┘
```

各子电路的具体职责：

| 子电路 | 验证内容 | 输入（witness） | 输出（public fields） |
| --- | --- | --- | --- |
| CoordKey | 协调者私钥/公钥配对 | coordPrivKey, coordPubKey | coordPubKeyHash, coordPrivKeyHash |
| ECDH | 共享密钥正确派生 | coordPrivKey, encPubKey, sharedKey | sharedKeyHash, sharedKeyBindingHash |
| Decrypt | 活跃状态密文解密正确 | coordPrivKey, c1, c2 | c1Hash, c2Hash, decryptIsOdd |
| Signature | 投票者 EdDSA 签名有效 | pubKey, r8, s, packedCommand | commandAuthHash, isSignatureValid |
| Step Core | 状态转换正确 | stateLeaf, votePath, 命令参数 | currentStateRoot, newStateRoot |
| Boundary | 批次承诺和哈希链 | stateRoots, salts, msgs | commitments, inputHash |


#### 4. 计票（`tally_votes_native`）

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Tally (单个电路，一次证明)                              │
│                                                                             │
│  输入 (witness):                                                            │
│    stateRoot            最终状态根（来自 Process Messages 的输出）             │
│    stateSalt            状态承诺的盐值                                       │
│    numSignUps           注册投票者数量                                       │
│    batchNum             当前处理第几批 5 个投票者 (0..4)                      │
│    stateLeaf[5][10]     本批次的 5 个状态叶子                                │
│    statePathElements    本批次在状态树中的 Merkle 路径                        │
│    votes[5][5]          投票权重: 5 个投票者 × 5 个选项                      │
│    currentResults[5]    前几批的累计结果                                     │
│    currentResultsRootSalt / newResultsRootSalt                              │
│                                                                             │
│  验证步骤:                                                                   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 1. 状态树包含证明                                                    │   │
│  │    • 对每个 stateLeaf[i] 计算哈希 → stateLeafHash[i]                 │   │
│  │    • 计算子根 subroot = H(stateLeafHash[0..4])                       │   │
│  │    • 从 subroot + pathElements + batchNum 重建 stateRoot             │   │
│  │    • assert(重建的根 == witness.stateRoot)                           │   │
│  │    → 证明这 5 个状态叶子确实在状态树中                                 │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 2. 状态承诺                                                          │   │
│  │    stateCommitment = H(stateRoot, stateSalt)                         │   │
│  │    → 将本证明链接到 Process Messages 的输出                           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 3. 投票根验证                                                        │   │
│  │    对每个投票者 i:                                                    │   │
│  │      voteRoot[i] = H(votes[i][0..4])                                │   │
│  │      assert(voteRoot[i] == stateLeaf[i].voteRootField)              │   │
│  │    → 证明投票权重与状态叶子中存储的一致                                │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 4. 当前计票承诺检查                                                   │   │
│  │    如果是第一批 (batchNum == 0):                                      │   │
│  │      assert(currentTallyCommitment == 0)                             │   │
│  │    否则:                                                              │   │
│  │      currentTallyCommitment = H(H(currentResults), currentSalt)      │   │
│  │    → 确保与前几批计票结果的连续性                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 5. 计票计算（二次投票）                                               │   │
│  │    对每个选项 j:                                                      │   │
│  │      newResults[j] = currentResults[j]                               │   │
│  │                     + Σ tallyVote(votes[i][j]) for i in 0..4         │   │
│  │    其中 tallyVote(v) = v × (v + MAX_VOTES)                          │   │
│  │    → 使用二次成本公式累加投票权重                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 6. 新计票承诺                                                        │   │
│  │    newTallyCommitment = H(H(newResults), newResultsRootSalt)         │   │
│  │    → 这就是最终存储到链上的值                                         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ 7. Input Hash                                                        │   │
│  │    inputHash = Poseidon(domain, packedVals, stateCommitment,         │   │
│  │                         currentTallyCommitment, newTallyCommitment)  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  公开输出 (12 个 felt):                                                      │
│    magic, version, circuitId, hashScheme,                                   │
│    stateTreeDepth, intStateTreeDepth, voteOptionTreeDepth,                  │
│    packedVals, stateCommitment,                                             │
│    currentTallyCommitment, newTallyCommitment, inputHash                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

**关键设计要点：**

- 计票按每批 5 个投票者处理（由 `intStateTreeDepth = 1` 决定，5^1 = 5）。在 2-1-1-3 参数下只有 1 个 signup，因此只需要 batch 0。
- Tally 输出中的 `stateCommitment` 必须等于 Process Messages 的 `newStateCommitment`——这就是承诺链连接两个阶段的方式。
- 实际投票总数（明文）永远不会存储到链上。链上只存储 `newTallyCommitment`。正确性由证明保证。


### 无需可信设置

与 zkSNARK（Groth16）系统需要举行仪式生成证明密钥/验证密钥不同，zkSTARK 的安全性仅依赖哈希函数的抗碰撞性（本系统使用 Poseidon 哈希）。编译后的 Cairo 程序（Sierra JSON）是唯一需要的产物——没有 `zkey`，没有"有毒废料"（toxic waste），除哈希函数外无额外信任假设。

---

## 第二部分：Starknet 端到端流程

### 整体架构

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                          链下（Operator 操作）                            │
│                                                                         │
│  1. 收集 round 消息 / 事件（注册、投票、停用）                               │
│  2. 为每个电路计算见证数据                                                │
│  3. 将输入序列化为 felt252 数组                                           │
│  4. 提交 programFile + inputFile 给 Atlantic 证明服务                     │
│  5. Atlantic 生成 STARK 证明并在 Starknet 上注册 fact                     │
│  6. Operator 调用链上合约消费已注册的 fact                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          链上（Starknet）                                 │
│                                                                         │
│  MockAmaciRound 合约：                                                   │
│    • 存储状态承诺（state、deactivate、tally）                              │
│    • 验证 fact 已在 Integrity FactRegistry 中注册                         │
│    • 检查公开输出与预期承诺值匹配                                          │
│    • 验证通过后推进轮次状态                                               │
└─────────────────────────────────────────────────────────────────────────┘
```

### 证明生成流水线

```text
┌────────────┐     ┌──────────────┐     ┌───────────────────────────────┐
│ Cairo      │     │ 序列化后的    │     │         Atlantic              │
│ 源码       │     │ 见证数据      │     │   （证明即服务）               │
│ (.cairo)   │     │ (felt252[])  │     │                               │
│            │     │              │     │  1. 执行 Cairo 程序            │
│  scarb     │     │  JS/任意     │     │  2. 生成执行轨迹（trace）       │
│  build     │     │  语言        │     │  3. 运行 Stone STARK 证明器    │
│    ↓       │     │    ↓         │     │  4. 在 Starknet 上验证证明     │
│ Sierra     │────→│ inputFile    │────→│  5. 在 Integrity FactRegistry │
│ JSON       │     │              │     │     注册 fact hash            │
│(programFile)     │              │     │                               │
└────────────┘     └──────────────┘     └───────────────────────────────┘
```

Operator 向 Atlantic 提交两个文件：

| 文件 | 内容 | 类比 |
| --- | --- | --- |
| `programFile` | 编译后的 Cairo 程序（Sierra JSON） | "电路"——每组参数固定一份 |
| `inputFile` | 序列化的见证 + 公开字段（felt252 数组） | "见证"——每轮不同 |

因此，在当前 Atlantic E2E 路径中，见证数据会提交到 Atlantic 的执行环境。proof 和链上 calldata 不包含这些私有输入，但第三方 prover service 本身是一个需要明确说明的执行边界。生产环境如果需要降低这一边界，可以选择自托管 Stone prover，并自行提交 Integrity 验证交易。

Atlantic 收到这两个文件后，执行以下完整流程：

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Atlantic 内部处理流程                                      │
│                                                                             │
│  输入: programFile (Sierra JSON) + inputFile (felt252[])                    │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ 1. Sierra → CASM 编译                                                 │  │
│  │    将 Sierra JSON 编译为 CASM（Cairo Assembly，最底层指令集）            │  │
│  │    同时计算 program hash = H(Sierra JSON)                             │  │
│  │    → program hash 用于链上合约验证"proof 来自正确的电路"                │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                         │                                                    │
│                         ▼                                                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ 2. Cairo VM 执行                                                      │  │
│  │    用 CASM + inputFile 在 Cairo VM 中运行程序                          │  │
│  │    → 产出: execution trace（每一步的寄存器状态）                        │  │
│  │    → 产出: memory（内存快照）                                          │  │
│  │    → 产出: public output（程序的返回值，即公开输出）                    │  │
│  │    如果程序中任何 assert 失败，执行中止，无法生成证明                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                         │                                                    │
│                         ▼                                                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ 3. Stone Prover 生成 STARK 证明                                       │  │
│  │    输入: trace + memory + public output                               │  │
│  │    输出: STARK proof                                                  │  │
│  │    → 证明 "存在一组输入使得程序正确执行并产生了该 public output"         │  │
│  │    → proof 和链上状态不直接包含 witness 明文                            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                         │                                                    │
│                         ▼                                                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ 4. Starknet L2 Proof Verification（x 笔交易）                         │  │
│  │    STARK proof 转换为 felt252 数组后有数千个元素，单笔 Integrity      │  │
│  │    验证调用不适合直接承载完整 proof，因此采用 split-calldata 模式：    │  │
│  │      交易 1~(x-1): 分批将 proof 数据写入链上临时存储                       │  │
│  │      交易 x:   调用验证函数，从临时存储读取完整 proof 并验证            │  │
│  │    Starknet 验证 proof 的数学正确性                                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                         │                                                    │
│                         ▼                                                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ 5. 注册 Fact                                                          │  │
│  │                                                                       │  │
│  │    Atlantic 使用 metadata wrapper 程序包装 Cairo 程序输出：           │  │
│  │                                                                       │  │
│  │    metadata_output 的内容:                                            │  │
│  │      • Atlantic 元数据（验证配置、安全参数）                           │  │
│  │      • child_program_hash（Cairo 程序的 program hash）                │  │
│  │      • Cairo 程序的完整 public output（嵌入其中）                    │  │
│  │                                                                       │  │
│  │    在 Integrity FactRegistry 合约中写入:                               │  │
│  │      fact_hash = H(metadata_program_hash, H(metadata_output))         │  │
│  │                                                                       │  │
│  │    注意: 链上注册的 fact 绑定的是 metadata 程序（Atlantic 的包装层），  │  │
│  │    不是直接绑定原始 Cairo 程序输出。AMACI 合约消费 fact 时需要：       │  │
│  │      1. 接收完整 metadata_output 作为参数                             │  │
│  │      2. 从中定位并提取 Cairo 程序公开输出（通过 circuit_id）          │  │
│  │      3. 验证 commitment 值                                            │  │
│  │      4. 重建 fact_hash 并查询 FactRegistry 确认已注册                 │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  最终状态: fact 已注册，Operator 可以调用 AMACI 合约消费该 fact             │
└─────────────────────────────────────────────────────────────────────────────┘
```

整个过程中，Operator 的私有数据（coordPrivKey 等）会进入 Atlantic 的执行环境，但不会出现在 proof、FactRegistry 或 AMACI 业务合约状态中。

### 关于 Metadata 包装层

Atlantic 不直接注册我们 amaci 程序的 fact，而是用一个 **metadata wrapper 程序**包装一层。metadata_output 中包含：
- Atlantic 自身的元数据（验证配置、安全参数）
- `child_program_hash`（Cairo 程序的 program hash）
- Cairo 程序的完整 public output（嵌入其中）

链上注册的 fact 绑定的是 `H(metadata_program_hash, H(metadata_output))`。AMACI 合约消费 fact 时，需要从 metadata_output 中提取 Cairo 程序公开输出并验证 commitment。

**未来 Operator 自己运行 prover**，则不需要 metadata 包装层。直接注册 `H(cairo_program_hash, H(cairo_public_output))` 即可。AMACI 合约已预留了两套入口函数：

```text
submit_process_messages_fact(...)                    ← Operator 自己跑 prover 时使用（直接绑定 Cairo 程序输出）
submit_process_messages_atlantic_metadata_fact(...)  ← 使用 Atlantic 时使用（需要解包 metadata）
```

### 关于 FactRegistry 存储的内容

FactRegistry 中**不存储 proof 本身**，只存储一个验证通过的凭证（fact hash）：

```text
Proof verification 过程:
  交易 1～(x-1): 把 proof 数据分批提交给 Integrity 验证合约
  交易 x:   验证合约验证 proof 的数学正确性
            → 验证通过后，在 FactRegistry 中写入:
              fact_hash = H(program_hash, H(public_output))
            → proof 数据本身不作为 FactRegistry 状态永久存储

FactRegistry 中一条记录的含义:
  "program_hash 对应的程序确实产出了这个 public_output，且已被验证通过。"

后续查询:
  任何人可通过 FactRegistry 查询 fact_hash 对应的 verification 记录
  AMACI 合约通过 get_all_verifications_for_fact_hash(...) 确认 proof 有效，
  并检查 security_bits 是否达到合约配置的 min_security_bits
```

### Integrity 合约组件（Starknet Sepolia）

Integrity 是 Herodotus/Atlantic 使用的链上 STARK 证明验证基础设施，由两个核心合约组成：

| 合约 | 地址 (Sepolia) | 作用 |
| --- | --- | --- |
| **Verifier** | `0x05e529706944049bb2be637a26a4d78b32e554ecaa54d0e608f2fa9f1472c516` | 接收 proof 数据，执行数学验证 |
| **FactRegistry (Satellite)** | `0x00421cd95f9ddabdd090db74c9429f257cb6bc1ccc339278d1db1de39156676e` | 存储验证通过的 fact hash，提供查询接口 |


**Verifier 合约的方法**：

| 方法 | 作用 | 使用场景 |
| --- | --- | --- |
| `verify_proof_initial` | 开始验证，提交第一批 proof 数据 | split-calldata 第 1 笔交易 |
| `verify_proof_step` | 继续提交 proof 数据（可调用多次） | split-calldata 第 2-8 笔交易 |
| `verify_proof_final` | 提交最后一批数据，触发最终验证并注册 fact | split-calldata 最后一笔交易 |
| `verify_proof_full` | 一次性提交完整 proof 并验证 | proof 足够小时的快捷方式 |


**FactRegistry 合约的查询方法**：

| 方法 | 作用 |
| --- | --- |
| `get_all_verifications_for_fact_hash(fact_hash)` | 给定 fact_hash，返回所有验证记录（包含 security_bits 和 verifier_config） |
| `get_verification(verification_hash)` | 给定 verification_hash，返回对应的验证记录（如果存在） |

AMACI 合约查询 FactRegistry 时，不是简单判断 fact 是否存在，而是检查安全位数是否达标：

```text
is_fact_hash_valid_with_security(fact_hash, min_security_bits):
  verifications = FactRegistry.get_all_verifications_for_fact_hash(fact_hash)
  for verification in verifications:
    if verification.security_bits >= min_security_bits:
      return true   ← 找到一条满足安全要求的验证记录
  return false      ← 没有达标的验证记录，拒绝
```

`min_security_bits` 是部署 AMACI wrapper/round 合约时配置的参数，不是协议里写死的常量。本轮 2-1-1-3 E2E 测试使用的是 `50`。

**调用链路**：

```text
Atlantic 提交 proof:
  tx 1:   Verifier.verify_proof_initial(settings, proof_part_1)
  tx 2-8: Verifier.verify_proof_step(proof_part_N)
  tx 9:   Verifier.verify_proof_final(proof_part_last)
              → 验证通过
              → Verifier 内部调用 FactRegistry.register(fact_hash)
              → 发出 FactRegistered 事件

AMACI 合约消费 fact:
  MockAmaciRound.submit_xxx_atlantic_metadata_fact(...)
      → 内部查询 FactRegistry 的 verification 记录
      → 存在满足 min_security_bits 的记录 → 更新 round 状态
      → 不存在达标记录 → 交易 revert
```

### 轮次生命周期

一个完整的 AMACI 轮次按以下顺序执行：

```text
  部署轮次合约
         │
         │  设置初始 signup state commitment / deactivate commitment / tally commitment
         ▼
  ┌─────────────────┐
  │   添加新密钥     │  消费 addNewKey fact，记录 nullifier
  │                 │  合约更新：state_commitment, keys_added
  └────────┬────────┘
           │
           ▼
  ┌──────────────────────┐
  │    处理停用消息       │  处理密钥停用批次（3 条消息）
  │                      │  合约更新：deactivate_commitment
  └────────┬─────────────┘
           │
           ▼
  ┌──────────────────────┐
  │    处理投票消息       │  处理投票批次（3 条消息）
  │                      │  合约更新：state_commitment
  └────────┬─────────────┘
           │
           ▼
  ┌─────────────────┐
  │      计票       │  计算最终投票结果
  │                 │  合约更新：tally_commitment, tally_submitted
  └─────────────────┘
```

每一步产生的证明，其公开输出中包含**当前**和**新**的承诺值。链上合约强制执行连续性检查：

```text
合约存储的承诺 == 证明中的当前承诺  →  验证通过
合约存储的承诺 = 证明中的新承诺    →  状态推进
```

### 承诺链（完整性保证）

整个轮次的安全性建立在承诺链之上。每个证明绑定一次状态转换，合约确保转换是顺序的：

```text
        处理停用                    处理投票消息                    计票
        ────────                   ────────────                   ────

公开输出：                        公开输出：                      公开输出：
  currentDeactivateCommitment       deactivateCommitment           stateCommitment
  newDeactivateCommitment ────→   （必须匹配）                    （必须匹配）
                                    currentStateCommitment
                                    newStateCommitment ──────→    （必须匹配）
                                                                   currentTallyCommitment
                                                                   newTallyCommitment
```

合约从不重放私有计算。它只验证：

1. fact hash 已在 Integrity FactRegistry 中注册
2. program hash 与该操作允许的电路匹配
3. 公开输出包含正确的 AMACI 电路标识符
4. 承诺值与合约当前存储的状态链接

### 链上合约的角色

`MockAmaciRound` 是 AMACI 轮次的链上状态机合约。它不执行任何投票处理逻辑——所有计算在链下完成并通过 zkSTARK 证明。合约只负责：验证 proof 已被 Integrity 确认、检查状态连续性、推进轮次状态。

**合约存储**：

```text
state_commitment              当前状态树承诺
deactivate_commitment         当前停用树承诺
tally_commitment              当前计票结果承诺
keys_added                    已接受的密钥注册数
message_batches_processed     已处理的投票批次数
deactivate_batches_processed  已处理的停用批次数
tally_submitted               最终计票是否已记录
allowed_program_hashes        合法电路 program hash 白名单
used_key_nullifiers           已消费的 nullifier 集合（防重放）
```

**E2E 轮次中合约的完整交互流程**：

本轮 E2E 使用 JS fixture 模拟用户端和 operator 端的数据生成。它不是前端钱包真实提交，也不是生产环境下的最终产品交互流程；它的目标是用确定性测试数据把协议级路径跑通：用户密钥和投票消息在本地生成，operator 将每个阶段的 Cairo input 提交给 Atlantic，Atlantic 在 Starknet 上验证 proof 并注册 fact，最后 `MockAmaciRound` 消费这些 fact 并推进链上状态。

本轮实际校验记录位于：

```text
target/e2e-round-flow-2113-resubmit-20260523T163136Z
```

实际部署和 Atlantic query：

| 项目 | 值 |
| --- | --- |
| MockAmaciRound | `0x035a58c97fd1a33ab945ccc76c2a2093eb9bdc0bb50ef9a451f3550d408dde3f` |
| addNewKey query | `01KSATVHX95VZ482Q488CG59D4` |
| processDeactivate query | `01KSATVW8P8FBWB3WHSQVFTXQJ` |
| processMessages query | `01KSATW8GSPAYA0QBD4EXBA5FN` |
| tally query | `01KSATWFCEPVQ5SAFGN8CXZNX7` |
| final state check | `chain-wrapper/final-state-check.json` |

**角色划分**：

| 阶段 | 业务角色 | 链上提交方 | 合约看到的内容 |
| --- | --- | --- | --- |
| addNewKey | 用户侧密钥更新/重新授权 | operator 或 relayer 可代交 | 已注册的 add-new-key fact、nullifier、新 state commitment |
| processDeactivate | operator 批处理停用消息 | operator | 已注册的 deactivate fact、旧/新 deactivate commitment |
| processMessages | operator 批处理投票消息 | operator | 已注册的 process-message fact、旧/新 state commitment |
| tally | operator 计票 | operator | 已注册的 tally fact、旧/新 tally commitment |

当前 E2E 中，链上 `sncast` 交易统一由测试账户提交；这只是测试执行方式，不改变协议角色。真实系统里，用户负责生成/授权自己的密钥和投票消息，operator 负责收集消息、生成证明、提交 fact 和推进 round。

**完整流程**：

```text
═══════════════════════════════════════════════════════════════════════════════
                         E2E Round 完整流程图
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 0: 部署 MockAmaciRound                                                 │
│                                                                             │
│ 配置:                                                                       │
│   • Integrity FactRegistry 地址                                             │
│   • 4 个电路的 program hash 白名单                                           │
│   • min_security_bits = 50（本轮 E2E 测试配置）                              │
│   • 初始 commitment 值                                                      │
│                                                                             │
│ 初始状态:                                                                    │
│   signupCount = 1, activeStateIndex = 1                                     │
│   state_commitment = initial    keys_added = 0                              │
│   deactivate_commitment = initial    tally_submitted = false                │
│   tally_commitment = 0                                                      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 1: Signup / 初始 Key（本地 fixture）                                      │
│                                                                             │
│ 用户侧:                                                                     │
│   用户客户端生成 AMACI 协议层 key pair。这个 key 不是 Starknet 钱包 key。      │
│   本轮 E2E 只有 1 个 signup 用户，对应 active state index = 1。               │
│                                                                             │
│ Operator / fixture:                                                          │
│   用该初始 key 构造初始 state leaf，写入 state tree，计算                    │
│   initial_state_commitment。部署 MockAmaciRound 时将该 commitment            │
│   作为初始 state_commitment 写入合约。                                       │
│                                                                             │
│ 链上合约:                                                                    │
│   只保存 initial_state_commitment，不保存用户 key 或明文 state leaf。         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 2: Add New Key                                                          │
│                                                                             │
│ 用户侧:                                                                     │
│   用户持有 signup 阶段的 oldPrivateKey，生成 newPubKey                       │
│   计算 nullifier = Poseidon(domain, oldPrivateKey, pollId)                  │
│   提供停用叶子 Merkle path + 重随机化密文等 witness                          │
│                                                                             │
│ 证明生成与提交 (用户自行完成，或委托 Operator):                               │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────────┐    │
│   │ 序列化   │───→│ Atlantic │───→│ Fact注册 │───→│ 调用合约         │    │
│   │ witness  │    │ 生成proof│    │FactRegistry   │submit_add_new_key│    │
│   └──────────┘    └──────────┘    └──────────┘    └──────────────────┘    │
│                                                                             │
│   注: Add New Key 的 witness 不包含 coordPrivKey，因此不依赖协调者私钥。     │
│   当前 E2E 测试中统一由 Operator 提交给 Atlantic，以简化流程。                │
│                                                                             │
│ Cairo 电路证明:                                                              │
│   • H(coordPubKey) == coordPubKeyHash                                       │
│   • nullifier = Poseidon(domain, oldPrivateKey, pollId)                     │
│   • deactivateLeaf = Poseidon(domain, c1Hash, c2Hash, sharedKeyHash)        │
│   • 从 deactivateLeaf + Merkle path 重建根 == deactivateRootHash            │
│   • 重随机化绑定: d1/d2 是 c1/c2 的合法重随机化                              │
│   • inputHash 正确聚合所有公开字段                                           │
│                                                                             │
│ 合约检查:                                                                    │
│   ✓ nullifier 未被使用过                                                    │
│   ✓ child_program_hash 在白名单中                                           │
│   ✓ FactRegistry 确认 fact 存在且 security_bits >= min_security_bits         │
│   ✓ metadata_output 中的 nullifier 与参数匹配                               │
│                                                                             │
│ 状态更新:                                                                    │
│   used_key_nullifiers[nullifier] = true                                     │
│   state_commitment = new_state_commitment                                   │
│   keys_added = 1                                                            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 3: Process Deactivate                                                   │
│                                                                             │
│ 本轮 fixture:                                                                │
│   构造 3 条停用消息，覆盖 messageBatchSize = 3 的停用处理路径。               │
│   真实系统中这些消息来自 round 的加密消息队列；本轮 E2E 中由 JS fixture       │
│   确定性生成，并序列化为 process-deactivate Cairo 程序输入。                 │
│                                                                             │
│ Operator 侧:                                                                │
│   ┌──────────────┐    ┌──────────┐    ┌──────────┐    ┌────────────────┐  │
│   │ 解密3条消息  │───→│ Atlantic │───→│ Fact注册 │───→│ 调用合约       │  │
│   │ 准备witness  │    │ 生成proof│    │FactRegistry   │submit_deactivate│ │
│   └──────────────┘    └──────────┘    └──────────┘    └────────────────┘  │
│                                                                             │
│ Cairo 电路证明:                                                              │
│   • ECDH 共享密钥正确                                                       │
│   • 停用命令解密正确                                                         │
│   • 停用授权签名有效                                                         │
│   • active 树 + deactivate 树更新正确                                       │
│                                                                             │
│ 合约检查:                                                                    │
│   ✓ self.deactivate_commitment == current_deactivate_commitment             │
│   ✓ self.state_commitment == current_state_commitment                       │
│   ✓ FactRegistry 确认 fact 存在且 security_bits >= min_security_bits         │
│   ✓ metadata_output 中的 commitment 值与参数一致                            │
│                                                                             │
│ 状态更新:                                                                    │
│   deactivate_commitment = new_deactivate_commitment                         │
│   deactivate_batches_processed = 1                                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 4: Process Messages                                                     │
│                                                                             │
│ 本轮 fixture:                                                                │
│   构造 3 条加密投票命令，真实系统中这些消息来自 round 的消息队列；            │
│   本轮 E2E 中由 JS fixture 本地生成，并序列化为 process-messages Cairo 输入。 │
│   最终投票状态: option0=2, option1=3, option2=5                              │
│   处理顺序: message index 2 → 1 → 0，index 0 是最新命令。                    │
│                                                                             │
│ Operator 侧:                                                                │
│   ┌──────────────┐    ┌──────────┐    ┌──────────┐    ┌────────────────┐  │
│   │ 解密3条消息  │───→│ Atlantic │───→│ Fact注册 │───→│ 调用合约       │  │
│   │ 逆序处理     │    │ 生成proof│    │FactRegistry   │submit_messages │  │
│   │ 更新state树  │    │          │    │          │    │                │  │
│   └──────────────┘    └──────────┘    └──────────┘    └────────────────┘  │
│                                                                             │
│ Cairo 电路证明:                                                              │
│   • ECDH / 解密 / 签名 / 状态转换 全部正确                                  │
│   • 消息逆序处理（最新消息优先生效）                                          │
│   • state_commitment: current → new                                         │
│   • deactivate_commitment 与链上值一致                                      │
│                                                                             │
│ 合约检查:                                                                    │
│   ✓ self.state_commitment == current_state_commitment                       │
│   ✓ self.deactivate_commitment == current_deactivate_commitment             │
│   ✓ FactRegistry 确认 fact 存在且 security_bits >= min_security_bits         │
│   ✓ metadata_output 中 output[11]=current, output[12]=new, output[13]=deact│
│                                                                             │
│ 状态更新:                                                                    │
│   state_commitment = new_state_commitment                                   │
│   message_batches_processed = 1                                             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Step 5: Tally                                                                │
│                                                                             │
│ Operator 侧:                                                                │
│   ┌──────────────┐    ┌──────────┐    ┌──────────┐    ┌────────────────┐  │
│   │ 读取最终     │───→│ Atlantic │───→│ Fact注册 │───→│ 调用合约       │  │
│   │ state树      │    │ 生成proof│    │FactRegistry   │submit_tally    │  │
│   │ 计算票数     │    │          │    │          │    │                │  │
│   └──────────────┘    └──────────┘    └──────────┘    └────────────────┘  │
│                                                                             │
│ Cairo 电路证明:                                                              │
│   • state leaves 在 state 树中（Merkle proof）                              │
│   • vote weights 与 state leaf 中的 voteRoot 一致                           │
│   • 二次投票公式计算正确: tallyVote(v) = v × (v + 10^24)                    │
│   • stateCommitment == processMessages 的 newStateCommitment                │
│                                                                             │
│ 合约检查:                                                                    │
│   ✓ tally_submitted == false（只能提交一次）                                 │
│   ✓ self.tally_commitment == current_tally_commitment                       │
│   ✓ self.state_commitment == current_state_commitment                       │
│   ✓ FactRegistry 确认 fact 存在且 security_bits >= min_security_bits         │
│                                                                             │
│ 状态更新:                                                                    │
│   tally_commitment = new_tally_commitment                                   │
│   tally_submitted = true                                                    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 轮次结束                                                                     │
│                                                                             │
│ 链上最终状态:                                                                │
│   keys_added = 1                                                            │
│   deactivate_batches_processed = 1                                          │
│   message_batches_processed = 1                                             │
│   total_facts_accepted = 4                                                  │
│   tally_submitted = true                                                    │
│                                                                             │
│ 链上只保存 commitment:                                                       │
│   state_commitment, deactivate_commitment, tally_commitment                 │
│                                                                             │
│ 明文投票结果 [2000...004, 3000...009, 5000...025, 0, 0] 保存在本地 fixture。 │
│ 公开 results 和 salt 后，可通过 H(results, salt) == tally_commitment         │
│ 复核计票结果；链上只保存 tally_commitment。                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**合约的核心设计原则**：

合约从不重放任何私有计算。它的验证逻辑可以归纳为三个检查：

```text
1. 状态连续性:  合约存储的 commitment == 调用参数中的 current_commitment
2. Proof 有效性: FactRegistry 中存在对应的 fact 且 security_bits 达标
3. 数据一致性:  metadata_output 中的关键公开字段 == 调用参数值
```

三个检查全部通过，合约才会更新状态。任何一个失败，交易 revert。这保证了：
- 不可能提交与当前链上 commitment 不连续的状态转换
- 不可能提交假 proof（FactRegistry 查询）
- 不可能篡改 proof 的公开输出（数据一致性）

### 成本结构

系统有三个独立的成本层。下表是本轮 Starknet Sepolia、2-1-1-3 参数、4 个 Atlantic query 下的观测值，不代表长期固定价格：

| 层级 | 内容 | 支付方 | 本轮观测值 |
| --- | --- | --- | --- |
| Atlantic 积分 | 证明服务费用 | Operator（链下） | 本轮 1200 credits，约 $12（4 个查询） |
| 证明验证 gas | STARK 证明验证 + fact 注册到 Starknet | Atlantic（链上） | 本轮 16.98583546779861 STRK |
| 业务合约 gas | AMACI 合约状态更新 | Operator（链上） | 本轮 0.2516417825771333 STRK（不含 deploy） |

证明验证成本主要来自 Atlantic 提交到 Starknet 的 STARK 验证交易。AMACI 业务逻辑本身（消费 fact 并更新承诺）非常轻量。

### 与 Groth16 AMACI 的对比

| 维度 | Groth16（circom） | zkSTARK（Cairo） |
| --- | --- | --- |
| 可信设置 | 需要（Powers of Tau + 电路特定仪式） | 不需要 |
| 电路语言 | Circom（R1CS 约束） | Cairo（可执行程序） |
| 证明生成 | 本地运行（rapidsnark） | Atlantic 或自托管 Stone prover |
| 链上验证 | Groth16 验证器合约（~200k gas） | Integrity 验证 proof 并注册 fact；业务合约查询 FactRegistry |
| 证明大小 | ~128 字节 | 较大；由 Atlantic 提交到 Integrity 验证，业务合约不直接接收完整 proof |
| 可组合性 | 有限 | 原生支持递归组合 |

### 总结

这次 Starknet 版本 AMACI 的实现证明了一条可行路径：把 AMACI 的核心状态转换拆解为可证明执行的 Cairo 程序，再由 Starknet 上的业务合约消费 Integrity FactRegistry 中已经验证过的 fact。链上合约不重放私有计算，也不保存投票明文；它只检查 fact 是否有效、program hash 是否匹配、公开输出中的 commitment 是否与当前链上状态连续。这样，复杂的投票处理和计票逻辑保留在可证明的链下执行中，链上只承担状态机和验证入口的职责。

在本轮 2-1-1-3 E2E 测试中，`signup -> vote -> deactivate -> vote -> processMsg -> tally` 的完整生命周期已经跑通：JS fixture 生成确定性业务数据和 witness，Atlantic 生成并验证 STARK proof，在 Starknet Sepolia 注册 fact，`MockAmaciRound` 依次消费 `addNewKey`、`processDeactivate`、`processMessages`、`tally` 四个 fact，并最终得到与本地 fixture 一致的链上 commitment 状态。这说明当前 Cairo 程序、Atlantic proof 路径、Integrity fact 注册、以及 AMACI wrapper 合约之间的协议连接是成立的。

当前实现仍然是协议级和合约级验证，而不是最终产品形态。使用 Atlantic 可以快速验证证明链路和成本模型，但 witness 会进入第三方执行环境；后续如果需要更强的执行边界，可以切换到自托管 Stone prover，并自行提交 Integrity 验证交易。接下来的优化重点，是进一步减少每轮需要消费的 fact 数量、优化 batch/递归聚合策略，并把当前 mock round 状态机演进为面向生产的 AMACI round 合约。
