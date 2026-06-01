# AMACI on Starknet：基于 zkSTARK 的匿名投票协议

## 概述

本文档描述 AMACI（Anonymous Minimal Anti-Collusion Infrastructure，匿名最小化反串谋基础设施）在 Starknet 上的架构与实现。系统使用 Cairo 程序生成 zkSTARK 证明，实现链上隐私投票：投票内容不会以明文出现在链上，投票处理和计票结果的正确性由零知识证明保证，并且无需可信设置（Trusted Setup）。

当前 `zkStark-amaci` 将 AMACI 的协议语义迁移到 Starknet 更适合的密码学原语上。当前 Cairo 程序使用 Starknet STARK curve、STARK ECDSA、STARK curve ECDH / ElGamal-style point encryption，以及 Starknet Poseidon 的 domain-separated hash/KDF。

需要先明确两个边界：

- **隐私边界**：AMACI/MACI 模型中的 Operator 负责解密和处理加密消息，因此 Operator 可以看到投票明文；隐私保护的对象主要是链上和公众观察者。使用 Atlantic 时，witness 也会进入 Atlantic 的执行环境。Operator 不能任意篡改状态转换、签名验证、解密结果或计票结果，因为当前 Cairo 程序会在电路内部约束这些密码学关系，并由 STARK proof 验证。
- **E2E 测试边界**：本文记录的是协议级和合约级 E2E 验证，使用 JS fixture 确定性生成用户密钥、消息和 witness，再提交给 Atlantic 生成并验证 proof。本轮测试已经包含真实 Starknet Sepolia 合约部署和 `MockAmaciRound` 消费 metadata fact 的链上交易；它仍不是最终产品的前端交互流程，也不是生产环境的唯一部署方式。

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
| **Poseidon** | 一种专为有限域算术设计的哈希函数。在 STARK 证明中效率极高（因为其内部结构全部由域上的加法和乘法组成）。当前实现使用 Starknet Poseidon，并对 Merkle tree、commitment、public input hash、message hash、nullifier hash、KDF/encryption stream 等用途做 domain separation。 |
| **Operator（协调者）** | 运行 AMACI 轮次的实体。负责收集加密消息、解密处理、生成证明并提交链上状态更新。Operator 可以看到投票明文，但无法篡改结果；ECDH、解密、签名、Merkle 路径和状态转换都受 Cairo 程序和 STARK proof 约束。 |
| **Atlantic** | Herodotus 提供的证明即服务（Proving-as-a-Service）平台。Operator 提交 programFile + inputFile，Atlantic 负责执行程序、生成 STARK 证明、在 Starknet 上验证并注册 fact。当前 E2E 使用 Atlantic 跑通端到端证明和 fact 注册流程；后续如果自托管 prover，Operator 可以在本地生成 Stone proof，再自行提交 Integrity 验证交易。使用 Atlantic 时，inputFile/witness 会进入 Atlantic 的执行环境，因此它是当前测试架构中的第三方执行边界。 |

### Cairo 程序的编译与执行

![01-compile-and-execute](./docs/diagrams/excalidraw/01-compile-and-execute.svg)

---

## 当前 Starknet-native 密码学口径

当前实现采用一套新的 Starknet-native AMACI 协议口径：

| 模块 | 当前实现 |
| --- | --- |
| 曲线 | Starknet STARK curve |
| 签名 | STARK ECDSA。Cairo 内部约束签名方程，使用显式 `R` 点 witness，验证 `s * R == H(command) * G + r * PubKey`，其中 `r = R.x` |
| ECDH | STARK curve scalar multiplication，协调者私钥和消息公钥在 Cairo 内部派生共享点 |
| 解密 | STARK curve ElGamal-style point relation 与 Poseidon stream 共同约束。Cairo 验证 `decrypted_point + shared == c2`，并用 shared point + nonce 派生的 Starknet Poseidon stream 约束 encrypted command 的明文字段 |
| Hash / KDF | Starknet Poseidon，并通过 domain separation 区分 public input hash、message hash、nullifier hash、signature hash、encryption stream 和各类 commitment |
| 公共输出 | 使用 native public output header，包括 magic、version、circuit id、hash scheme 等字段，供链上 wrapper 合约识别和绑定 |

因此，当前 Cairo 程序保留 AMACI 的状态机语义和承诺链设计，但密码学原语使用 Starknet-native 路线。

## 第一部分：amaci Cairo 电路架构

### 什么是 Cairo 电路

在本系统中，"电路"指的是可被证明执行的 Cairo 程序，实际实现上，它们是 Cairo 源码和编译后的 Sierra JSON。每个程序接收私有见证数据（witness）作为输入，执行密码学验证逻辑，并输出一组公开承诺值（commitment）。程序通过 `scarb build` 编译为 Sierra JSON，STARK 证明器基于程序的执行轨迹生成证明。

![02-cairo-circuit](./docs/diagrams/excalidraw/02-cairo-circuit.png)

### 电路参数（2-1-1-3）

当前实现使用固定参数集：

| 参数 | 值 | 含义 |
| --- | ---: | --- |
| stateTreeDepth | 2 | 5 叉 Merkle 树，25 个状态叶子 |
| intStateTreeDepth | 1 | 每个 tally 批次处理 5 个叶子 |
| voteOptionTreeDepth | 1 | 每个投票者有 5 个投票选项 |
| messageBatchSize | 3 | 每个证明批次处理 3 条加密消息 |

### 电路族

系统由四个电路族组成，分别负责 AMACI 轮次中的可证明状态转换。下面的顺序是模块说明顺序，不是 round 生命周期顺序；标准生命周期见后文 `signup -> deactivate -> processDeactivate -> addNewKey -> vote -> processMessages -> tally`。

![03-circuit-families](./docs/diagrams/excalidraw/03-circuit-families.png)

#### 1. 处理停用消息（`process_deactivate_stage_native`）

证明一批 3 条停用消息被正确处理。对每条消息，电路验证：

- **ECDH**：在 STARK curve 上用协调者私钥和消息公钥派生共享点
- **解密**：在 Cairo 内验证 STARK curve decrypt point relation，确保加密命令解密后为合法停用请求
- **签名**：投票者的 STARK ECDSA 签名授权了该停用操作，签名方程在 Cairo 内部约束
- **状态转换**：活跃状态树和停用树被正确更新

**公开输出**：当前/新停用承诺、消息哈希链、状态根。


对应文件：

| 文件 | 角色 |
| --- | --- |
| `native_process_deactivate.cairo` | Boundary — 批次级别的承诺和哈希链约束 |
| `native_process_deactivate_components.cairo` | 子组件 — CoordKey / ECDH / Signature / Decrypt |
| `native_process_deactivate_step_core.cairo` | Step Core — 单条停用消息的状态转换 |
| `native_process_deactivate_stage.cairo` | Stage 入口 — 组合所有模块并验证交叉链接 |



![05-process-deactivate-stage](./docs/diagrams/excalidraw/05-process-deactivate-stage.png)


#### 2. 添加新密钥（`add_new_key_native`）

![04-add-new-key](./docs/diagrams/excalidraw/04-add-new-key.png)

证明一次用户侧密钥更新 / 重新授权被正确处理。电路验证：

- **旧密钥授权 / nullifier**：旧私钥和 poll id 派生 nullifier，防止同一旧 key 在同一 poll 中重复注册；旧私钥还会与协调者公钥派生 shared key，并和 deactivate leaf 绑定。
- **新密钥绑定**：新 STARK curve 公钥不会与旧 key 混用；电路输出 `new_pub_key_hash` 并把它纳入 input hash / native public output，供合约消费 fact 时绑定。
- **停用证明**：旧 key 对应的 deactivate leaf 和 Merkle path 正确，说明旧 key 已进入停用集合。
- **重随机化**：旧密钥相关的密文在 STARK curve 上完成 ElGamal-style rerandomization 绑定。
- **公开输出绑定**：当前 `add_new_key_native` 输出 `deactivate_root_hash`、`coord_pub_key_hash`、`nullifier`、`new_pub_key_hash`、`rerandomize_binding_hash`、`poll_id` 和 `input_hash` 等公开字段；生产合约据此消费 nullifier、登记新 key 并推进业务状态。


#### 3. 处理投票消息（`process_messages_stage_native`）

证明一批 3 条投票消息被正确处理。对每条消息：

- **ECDH**：在 STARK curve 上派生投票者消息公钥与协调者私钥之间的共享点
- **解密**：在 Cairo 内验证 STARK curve decrypt point relation，并用 Starknet Poseidon stream 约束 encrypted command 的明文字段
- **签名**：STARK ECDSA 签名验证，Cairo 约束 `s * R == H(command) * G + r * PubKey`
- **状态转换**：检查 stateIndex、active/deactivate 标记、pollId 和 nonce；合法消息更新投票权重、余额、nonce，已停用旧 key 的消息不改变结果

**公开输出**：当前/新状态承诺、停用承诺、消息哈希链。

对应文件：

| 文件 | 角色 |
| --- | --- |
| `native_process_messages.cairo` | Boundary — 批次级别的承诺和哈希链约束 |
| `native_process_message_components.cairo` | 子组件 — CoordKey / ECDH / Decrypt / Signature |
| `native_process_message_step_core.cairo` | Step Core — 单条消息的完整状态转换 |
| `native_process_messages_stage.cairo` | Stage 入口 — 组合所有模块并验证交叉链接 |

完整流程图：

![06-process-messages-stage](./docs/diagrams/excalidraw/06-process-messages-stage.png)


各子电路的具体职责：

| 子电路 | 验证内容 | 输入（witness） | 输出（public fields） |
| --- | --- | --- | --- |
| CoordKey | 协调者私钥/公钥配对 | coordPrivKey, coordPubKey | coordPubKeyHash, coordPrivKeyHash |
| ECDH | STARK curve 共享点正确派生 | coordPrivKey, encPubKey, sharedKey | sharedKeyHash, sharedKeyBindingHash |
| Decrypt | STARK curve 密文点关系和命令解密正确 | coordPrivKey, c1, c2, decryptedPoint, encryptedCommand | c1Hash, c2Hash, decryptIsOdd, decryptBindingHash |
| Signature | 投票者 STARK ECDSA 签名有效 | pubKey, rPoint, s, packedCommand | commandAuthHash, signatureValid |
| Step Core | 状态转换正确 | stateLeaf, votePath, 命令参数 | currentStateRoot, newStateRoot |
| Boundary | 批次承诺和哈希链 | stateRoots, salts, msgs | commitments, inputHash |


#### 4. 计票（`tally_votes_native`）

![07-tally](./docs/diagrams/excalidraw/07-tally.png)

**关键设计要点：**

- 计票按每批 5 个状态叶子处理（由 `intStateTreeDepth = 1` 决定，5^1 = 5）。如果本轮占用超过 5 个 stateIndex，需要多批 tally；
- Tally 输出中的 `stateCommitment` 必须等于 Process Messages 的 `newStateCommitment`——这就是承诺链连接两个阶段的方式。
- 实际投票总数（明文）永远不会存储到链上。链上只存储 `newTallyCommitment`。正确性由证明保证。


### 无需可信设置

与 zkSNARK（Groth16）系统需要举行仪式生成证明密钥/验证密钥不同，zkSTARK 路线不需要 trusted setup。编译后的 Cairo 程序（Sierra JSON）是主要证明产物，没有 `zkey`，也没有"有毒废料"（toxic waste）。

需要区分证明系统假设和协议密码学假设：STARK 证明系统本身依赖哈希/FRI 等公开安全假设；AMACI 业务协议还依赖 Starknet STARK curve 离散对数假设、STARK ECDSA 安全性、STARK curve ECDH 安全性，以及 Starknet Poseidon 在各 domain 下作为 hash/KDF 的安全性。

---

## 第二部分：Starknet 端到端流程

### 整体架构

![08-overall-architecture](./docs/diagrams/excalidraw/08-overall-architecture.png)

### 证明生成流水线

![09-proof-pipeline](./docs/diagrams/excalidraw/09-proof-pipeline.png)

Operator 向 Atlantic 提交两个文件：

| 文件 | 内容 | 类比 |
| --- | --- | --- |
| `programFile` | 编译后的 Cairo 程序（Sierra JSON） | "电路"——每组参数固定一份 |
| `inputFile` | 序列化的见证 + 公开字段（felt252 数组） | "见证"——每轮不同 |

因此，在当前 Atlantic E2E 路径中，见证数据会提交到 Atlantic 的执行环境。proof 和链上 calldata 不包含这些私有输入，但第三方 prover service 本身是一个需要明确说明的执行边界。生产环境如果需要降低这一边界，可以选择自托管 Stone prover，并自行提交 Integrity 验证交易。

Atlantic 收到这两个文件后，执行以下完整流程：

![09b-atlantic-internal-pipeline](./docs/diagrams/excalidraw/09b-atlantic-internal-pipeline.png)

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
| `verify_proof_step` | 继续提交 proof 数据（可调用多次） | split-calldata 中间交易，数量取决于 proof 和 calldata 大小 |
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
  tx 1:      Verifier.verify_proof_initial(settings, proof_part_1)
  tx 2..n-1: Verifier.verify_proof_step(proof_part_N)
  tx n:      Verifier.verify_proof_final(proof_part_last)
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

![10-round-lifecycle](./docs/diagrams/excalidraw/10-round-lifecycle.png)

每一步产生的证明，其公开输出中包含**当前**和**新**的承诺值。链上合约强制执行连续性检查：

```text
合约存储的承诺 == 证明中的当前承诺  →  验证通过
合约存储的承诺 = 证明中的新承诺    →  状态推进
```

### 承诺链（完整性保证）

整个轮次的安全性建立在承诺链之上。每个证明绑定一次状态转换，合约确保转换是顺序的：

![11-commitment-chain](./docs/diagrams/excalidraw/11-commitment-chain.png)

合约从不重放私有计算。它只验证：

1. fact hash 已在 Integrity FactRegistry 中注册
2. program hash 与该操作允许的 Cairo 程序匹配
3. metadata output 中的 child program hash、native public output header、circuit id、hash scheme 与预期匹配
4. 公开输出中的 commitment、nullifier、batch counter 等关键字段与调用参数一致
5. 承诺值与合约当前存储的状态链接

### 链上合约的角色

`MockAmaciRound` 是 AMACI 轮次的链上状态机合约。它不执行任何投票处理、签名验证、解密或计票逻辑，所有这些计算都在 Cairo 程序中完成并通过 zkSTARK 证明。合约只负责：验证 proof 已被 Integrity 确认、检查 program hash 和 metadata output 绑定、检查状态连续性、推进轮次状态。

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

本轮 E2E 使用 JS fixture 模拟用户端和 operator 端的数据生成。它不是前端钱包真实提交，也不是生产环境下的最终产品交互流程；它的目标是用确定性测试数据把协议级路径跑通：用户密钥和投票消息在本地生成，operator 将每个阶段的 Cairo input 提交给 Atlantic，Atlantic 在 Starknet 上验证 proof 并注册 fact，最后真实部署在 Starknet Sepolia 上的 `MockAmaciRound` 消费这些 fact 并推进链上状态。

**完整流程**：

![12-e2e-round-flow](./docs/diagrams/excalidraw/12-e2e-round-flow.png)

**合约的核心设计原则**：

合约从不重放任何私有计算。它的验证逻辑可以归纳为三个检查：

```text
1. 状态连续性:  合约存储的 commitment == 调用参数中的 current_commitment
2. Proof 有效性: FactRegistry 中存在对应的 fact 且 security_bits 达标
3. 数据一致性:  program hash、native output header、circuit id、hash scheme 和关键公开字段 == 调用参数值
```

三个检查全部通过，合约才会更新状态。任何一个失败，交易 revert。这保证了：
- 不可能提交与当前链上 commitment 不连续的状态转换
- 不可能提交假 proof（FactRegistry 查询）
- 不可能篡改 proof 的公开输出（数据一致性）


### 与 Groth16 AMACI 的对比

| 维度 | Groth16（circom） | zkSTARK（Cairo） |
| --- | --- | --- |
| 可信设置 | 需要（Powers of Tau + 电路特定仪式） | 不需要 |
| 电路语言 | Circom（R1CS 约束） | Cairo（可执行程序） |
| 密码学原语 | BabyJubJub、EdDSA、Circom Poseidon | STARK curve、STARK ECDSA、Starknet Poseidon |
| 协议等价性 | 原始 AMACI / MACI 电路路线 | Starknet-native AMACI 变体，不追求 byte-for-byte 等价 |
| 证明生成 | 本地运行（rapidsnark） | Atlantic 或自托管 Stone prover |
| 链上验证 | Groth16 验证器合约（~200k gas） | Integrity 验证 proof 并注册 fact；业务合约查询 FactRegistry |
| 证明大小 | ~128 字节 | 较大；由 Atlantic 提交到 Integrity 验证，业务合约不直接接收完整 proof |
| 可组合性 | 有限 | 原生支持递归组合 |

### TBD：当前电路与协议仍需确认的生产化边界

当前 Starknet-native AMACI 已经把 ECDH、解密、签名验证、ElGamal-style rerandomize、nullifier、message hash、commitment 链等关键关系放进 Cairo 程序中约束，不再依赖 operator 传入的有效性 flag；但它已经是一个新的 Starknet-native AMACI 协议口径，而不是 BabyJubJub/Circom 版本的逐约束迁移。因此在进入生产前，还需要补齐以下确认项：

- **密码学审计**：重点审计 Stark curve 标量范围、签名 `r/s/R` 的 canonical 约束、签名等式、ECDH shared point、ElGamal-style decrypt/rerandomize 绑定、Poseidon stream 的 nonce/domain separation，以及 `poll_id` / nullifier / new public key 是否在所有路径中完整绑定。
- **协议兼容边界**：明确 Starknet-native key、message、signature、ciphertext 与旧 BabyJubJub/Circom 数据完全不兼容；前端、operator、witness 生成器和合约调用链必须全部切换到同一套 Starknet-native 格式。
- **Prover 信任边界**：如果使用 Atlantic，proof correctness 仍由 STARK proof + Integrity FactRegistry + 合约绑定检查保证，但 witness 会进入 Atlantic 的执行环境；如果生产环境不能接受第三方看到 witness，应切换到自托管 Stone prover 并自行提交 Integrity verification。
- **参数泛化**：当前完整 E2E 使用 2-1-1-3 参数集，需要在更大规模参数集上补齐 Cairo program、operator fixture、Atlantic/Stone proving 和链上 fact 消费测试。

### 总结

Starknet-native AMACI 的实现证明了一条可行路径：把 AMACI 的核心状态转换和关键密码学关系拆解为可证明执行的 Cairo 程序，再由 Starknet 上的业务合约消费 Integrity FactRegistry 中已经验证过的 fact。链上合约不重放私有计算，也不保存投票明文；它只检查 fact 是否有效、program hash 是否匹配、metadata output 是否绑定正确、公开输出中的 commitment 是否与当前链上状态连续。这样，复杂的投票处理、ECDH、解密、签名验证和计票逻辑都保留在可证明的链下执行中，链上只承担状态机和验证入口的职责。

当前实现已经切换到 Starknet 原生曲线体系：用户公钥、协调者公钥、ECDH 共享点、ElGamal-style 密文点关系和 STARK ECDSA 签名都建立在 Starknet STARK curve 上，hash/KDF/encryption stream 则统一使用 Starknet Poseidon 并做 domain separation。也就是说，Cairo 程序不再依赖 BabyJubJub / EdDSA / BN254 兼容路径，这些密码学关系会在 Cairo 执行中重新计算或约束，证明失败就无法产生可被链上合约接受的 fact。

当前实现仍然是协议级和合约级验证，而不是最终产品形态。使用 Atlantic 可以快速验证证明链路和成本模型，但 witness 会进入第三方执行环境；后续如果需要更强的执行边界，可以切换到自托管 Stone prover，并自行提交 Integrity 验证交易。接下来的优化重点，是进一步减少每轮需要消费的 fact 数量、优化 batch/递归聚合策略，并把当前 mock round 状态机演进为面向生产的 AMACI round 合约。