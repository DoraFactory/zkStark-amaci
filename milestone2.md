# Milestone 2: AMACI Proof Granularity Optimization

## 背景

当前 Starknet-native AMACI 已经把原来的非 native 密码学路径迁移到 Cairo/STARK 更友好的实现上：

- 使用 `felt252` / Starknet-friendly 数据结构。
- 使用 Starknet Poseidon 等 native-friendly hash。
- 组件 proof 已经可以通过 Atlantic 路径提交并在链上注册 fact。
- wrapper 合约可以消费这些 fact，并把 `add new key -> process messages -> tally` 的 round 流程串起来。

当前方案已经证明可行，但 proof 粒度仍然比较碎。以当前 5 条 message 的 `processMessages` batch 为例，证明层不是一个 proof，而是拆成多个 component proof：

```text
processMessages batch
  coord-key-native        1 proof
  ecdh-native             5 proofs
  decrypt-native          5 proofs
  signature-native        5 proofs
  step-core-native        5 proofs
  boundary-native         1 proof
```

因此一个 `processMessages` batch 当前需要 22 个 proof/fact。完整最小业务 round 中还包含：

```text
add-new-key-native        1 proof
processMessages           22 proofs
tally-native              1 proof
```

也就是 24 个业务 proof/fact。这个结构便于调试和控制单个 prover job 的内存，但会带来较多 Atlantic query、链上 fact、wrapper 调用和成本统计复杂度。

Milestone 2 的目标是优化 proof 粒度，在不重新引入旧方案巨大 prover 压力的前提下，减少 proof/fact 数量和链上业务调用成本。

## 当前方案与目标方案的区别

当前方案是“多 proof + wrapper 串联校验”：

```text
多个 component proof
  -> Atlantic/Integrity 注册多个 fact
  -> AMACI wrapper 逐个消费 fact
  -> wrapper 检查 public output 链接关系
  -> 更新 round state
```

目标方案不是立即做一个巨大 round proof，而是分阶段收敛 proof 粒度：

```text
当前 component proofs
  -> fused single-message proof
  -> batch message proof
  -> operation-level aggregate fact
```

## 三种优化层级

### 1. Fused Single-Message Proof

把每条 message 内部的多个 proof 合并成一个 proof。

当前每条 message 大致需要：

```text
ecdh proof
decrypt proof
signature proof
step-core proof
```

中间方案变成：

```text
process_message_step_native proof
```

这个 proof 内部完成：

```text
ECDH
decrypt
signature/auth check
command apply
state root update
```

对于 5 条 message 的 batch，proof 数量可以从：

```text
coord-key 1 + ecdh 5 + decrypt 5 + signature 5 + core 5 + boundary 1 = 22
```

降到：

```text
coord-key 1 + step-native 5 + boundary 1 = 7
```

这是最稳的第一步。它可以先测出“一条完整 message”的真实 Stone/Atlantic 成本，再判断是否适合继续做 batch。

### 2. Process Messages Batch Native

`processMessagesBatchNative` 是一个 batch 直接生成一个 proof，不是先生成多个小 proof 再聚合。

它的目标是：

```text
process_messages_batch5_native
  直接处理 5 条 message
  直接输出 batch 前后的 state commitment
```

理想形态：

```text
processMessages batch
  -> 1 proof
```

或者更保守的形态：

```text
coord-key
batch5-core
boundary
```

这种方案会减少 Atlantic query、fact 数量和 wrapper 调用数量，但会增加单个 prover job 的 trace 和内存压力。因此 batch size 不应该一开始写死为无限大，而应先固定当前测试规模：

```text
batch_size = 5
```

后续根据 Stone/Atlantic 数据决定是否支持更大的 batch。

### 3. Operation-Level Aggregate Fact

这是更后面的目标。它不是直接把业务逻辑放进一个大 Cairo 程序，而是让多个 component proof 或 batch proof 最终产生一个业务级 aggregate fact：

```text
add-key aggregate fact
process-messages aggregate fact
tally fact
```

这可以让 AMACI wrapper 只消费业务级 fact，而不是每个 component fact。

这条路可能需要：

- 新的 Cairo aggregator circuit。
- 或 Atlantic/Herodotus 提供的 bootloaded/recursive aggregate 路径。
- 或链下严格构造 metadata-level proof/fact，并让 wrapper 接受对应的 fact hash 语义。

它适合生产化后期，但不应该作为 Milestone 2 的第一步。

## Batch Native 与 Proof Aggregation 的区别

这两个概念容易混淆。

Batch native 是：

```text
一个 Cairo 程序直接处理 N 条 message
一次生成一个 proof
```

Proof aggregation 是：

```text
先生成多个小 proof
再用递归/聚合证明把它们合成一个 proof/fact
```

所以它们的区别是：

| 方案 | 输入 | 输出 | 主要影响 |
| --- | --- | --- | --- |
| batch native | 原始业务输入 | 1 个 batch proof | 减少 proof 数，但单 proof 更重 |
| proof aggregation | 多个已生成 proof/fact | 1 个 aggregate proof/fact | 保留小 proof，可减少链上消费粒度 |

Milestone 2 优先考虑 batch native / fused proof，因为它直接减少 Atlantic query 数和 component fact 数；aggregation 作为后续生产化方向。

## 自建 Stone Prover 的影响

如果后续我们自己跑 Stone prover，batch proof 一定会增加单个 prover job 的内存压力。

当前小 proof 模式的特点：

```text
单个 proof 内存低
proof 数量多
链上 fact 多
调度复杂
```

Batch proof 的特点：

```text
单个 proof 内存高
proof 数量少
链上 fact 少
调度简单
```

所以 batch 不是无脑更轻，而是把压力从“很多小任务”转移到“少量大任务”。

Milestone 2 需要每次新增 proof 粒度时记录这些指标：

```text
n_steps
STARK degree bound
peak RSS
proof size
Integrity split calldata size
initial / step / final calldata felts
Atlantic query cost
Atlantic verification tx fee
AMACI wrapper submit fee
```

## 当前已落地的第一步

已经新增 `process-messages-stage-native`，这是一个阶段级 native executable。

它不是递归聚合 proof，也不是 Atlantic fact 聚合；它是把当前 `processMessages` batch 内部原本需要 wrapper 串联的 component 逻辑，直接放进一个 Cairo 程序中一次执行：

```text
process-messages-stage-native
  boundary
  coord-key
  ecdh[0..4]
  decrypt[0..4]
  signature[0..4]
  step-core[0..4]
  internal link checks
  -> same ProcessMessages boundary public output
```

这个 stage proof 的 public output 仍然保持 `process-messages-boundary-native` 的 16 个 public felts 格式，因此业务合约侧仍然可以复用 `submit_process_messages_atlantic_metadata_fact` 的状态推进语义。区别是部署 round/wrapper 时，`process_messages_program_hash` 应配置为 `process_messages_stage_native` 对应的 Atlantic program hash，而不是原来的 boundary-only program hash。

本地 smoke 数据：

```text
circuit: process-messages-stage-native
executable: process_messages_stage_native
public output felts: 16
scarb execute steps: 34,850
max memory address: 63,453
poseidon builtin: 568
cairo1-run argument felts: 1,435
local Scarb/Stwo execution id: 177
local Scarb/Stwo proof size: 13,261,877 bytes
```

已验证：

```bash
npm test
RUN_CAIRO_EXECUTION_TESTS=1 node --test --test-name-pattern "ProcessMessages stage" tests/cairo-execution.test.mjs
npm run stone:air:circuit -- --circuit process-messages-stage-native --out-dir target/stone-air/process-messages-stage-native-smoke --skip-cairo1-run
npm run prove:process-messages-stage-native -- --out-dir target/cairo-proof/process-messages-stage-native-smoke
```

Atlantic 提交记录：

| query id | declared job size | status | 说明 |
| --- | --- | --- | --- |
| `01KS2X7M9ZTJ17AY4A924AMEM1` | `S` | `FAILED` | proof/artifact 已生成，但 L2 verification 阶段返回 `UNRECOVERABLE_RABBIT_MQ_ERROR`，同时 summary 显示 `isJobSizeValid=false`。 |
| `01KS4RG6Z9HFDZTPAFV7RZSXZK` | `M` | `FAILED` | L2 verification 阶段失败：`CALLDATA_TOO_LARGE`，`initial` calldata 为 5629 felts，超过 Atlantic 当前 Starknet L2 verifier path 的 5000 felt 限制。 |
| `01KS5DETH05WZ9BSDE7GQTJ8XX` | `M` + `herodotus_sn_grower` | `FAILED` | grower hint 没有解决该 proof 的 `initial` calldata 过大问题，仍然卡在 5629 felts。 |

两次提交对应的 child program hash / fact hash 一致：

```text
program hash: 0x9a79b999a01a9c5e0eb7ea14328362bc31bb52cb56fc68b0e8453b8db10e00
integrity fact hash: 0xa00cc50839e1514c45f538dc72384c8fd44d5c54fe4feaccde0e1c866417cc
sharp fact hash: 0xbc3de214a359a7d5bfe486de8b790df6cd8851ea2754992a6c90eaa64caef00b
```

当前 stage Atlantic artifact 体量：

```text
programFile ~= 7.0 MiB
inputFile ~= 44 KiB
input felts = 1,435
```

这说明 5-message stage 虽然本地可证明，但直接走 Atlantic L2 verification 仍然太大，不能作为当前的可上链优化方案。

## 已验证的改进：ProcessMessages Segment Stage

为绕开 5-message stage 的 Atlantic `initial` calldata 限制，已经新增统一的分段 executable：

```text
process_messages_stage_segment_native
```

它使用同一个 Cairo program，通过第一个参数 `segment_kind` 区分：

```text
segment_kind = 2  -> head2: messages[0..1]
segment_kind = 3  -> tail3: messages[2..4]
```

也就是说，一个 5-message `processMessages` batch 从 22 个 component proof 降到 2 个 segment proof：

```text
tail3 stage proof: message 2,3,4
head2 stage proof: message 0,1
```

两个 segment proof 的 public output 仍然复用 `ProcessMessagesNativeBoundary` 的 16 个 felts，因此 wrapper 状态推进语义不变：

```text
current_state_commitment -> new_state_commitment
current_deactivate_commitment unchanged
batch_start_hash -> batch_end_hash
```

本地 smoke 数据：

| circuit | executable | cairo args felts | scarb execute steps | poseidon builtin | public output felts |
| --- | --- | ---: | ---: | ---: | ---: |
| `process-messages-stage-head2-native` | `process_messages_stage_segment_native` | 898 | 17,505 | 239 | 16 |
| `process-messages-stage-tail3-native` | `process_messages_stage_segment_native` | 898 | 21,430 | 348 | 16 |

本地 Scarb/Stwo proof 也已通过：

| circuit | execution id | proof size |
| --- | ---: | ---: |
| `process-messages-stage-head2-native` | 183 | 13,458,389 bytes |
| `process-messages-stage-tail3-native` | 184 | 13,475,551 bytes |

Stone/Atlantic program input 数据：

```text
output dir: target/atlantic-process-messages-stage-segments-20260521T143706Z
shared programFile size: ~6.5 MiB
head2 input felts: 898
tail3 input felts: 898
shared programFile sha256:
  a4f8587779c6ae30674ec9272799c83b0c0bdf5bbf01fec449aa29b8f00c109b
```

注意：head2/tail3 必须复用同一个 Sierra `programFile`，否则临时 Cairo package 路径不同可能导致 Sierra 内部 ids 不同，最终 program hash 也可能不同。当前 `export:atlantic-query` 已支持 `--program-file` 覆盖，用于这个共享 programFile 场景。

已验证：

```bash
scarb build
node tools/run-cairo-execute.mjs --circuit process-messages-stage-head2-native --out-dir target/cairo-execute/process-messages-stage-head2-native-smoke --timeout-ms 900000
node tools/run-cairo-execute.mjs --circuit process-messages-stage-tail3-native --out-dir target/cairo-execute/process-messages-stage-tail3-native-smoke --timeout-ms 900000
RUN_CAIRO_EXECUTION_TESTS=1 node --test --test-name-pattern "ProcessMessages stage" tests/cairo-execution.test.mjs
npm test
```

Atlantic 提交尝试和最终结果：

| segment | query resource id | declared job size | submit status | 说明 |
| --- | --- | --- | --- | --- |
| `head2` | `01KS5FGQZ34WQQBE4FQGKWATQP` | `M` | `NOT_SUBMITTED` | Atlantic 返回 `402 insufficient_credits`，需要 300 credits。没有返回正式 `atlanticQueryId`。 |
| `tail3` | `01KS5FH0C9EWVZFAP4D7090G1Q` | `M` | `NOT_SUBMITTED` | Atlantic 返回 `402 insufficient_credits`，需要 300 credits。没有返回正式 `atlanticQueryId`。 |
| `head2` | `01KS75Y4SGD3GREZEG2KTD700Y` | `M` | `DONE` | 2026-05-22 使用新 key 提交成功，并完成 `PROOF_VERIFICATION_ON_L2`。Console: `https://www.herodotus.cloud/en/atlantic/01KS75Y4SGD3GREZEG2KTD700Y` |
| `tail3` | `01KS75YAMCXXBTJC8S8K6G1WFS` | `M` | `DONE` | 2026-05-22 使用新 key 提交成功，并完成 `PROOF_VERIFICATION_ON_L2`。Console: `https://www.herodotus.cloud/en/atlantic/01KS75YAMCXXBTJC8S8K6G1WFS` |

新提交的两个 segment 复用了同一个 program hash：

```text
program hash:
  0x629bd3434387bfd139c424ac566f46cfe9cb7efd7dabef9874c3a6cb96a33fc

head2:
  completed at: 2026-05-22T06:43:22.326Z
  transaction id: 01KS75YJX697YG4GKA6M095Z1A
  integrity fact hash: 0x41f750313315c5fbd985277421fef7b74ccfc834d0234cabc24de8984a8264
  sharp fact hash: 0x9746801ab13b62905703901546e7368f0d804d3b3f2790e0a8a204b57ce0a7aa
  status dir: target/atlantic-process-messages-stage-segments-20260521T143706Z/head2/atlantic-query-check-M-20260522T062831Z

tail3:
  completed at: 2026-05-22T06:43:56.480Z
  transaction id: 01KS75YQWCXGYQ666KRXJK87R4
  integrity fact hash: 0x75fcda72a0c1c163e963853a1c75e0f8ca65a419dac80cb8ee1e068d18e9366
  sharp fact hash: 0x5dcf5c44ebf9f05e3e035e86c6233a492984b9e1ff1115f5c59dcabda95d074c
  status dir: target/atlantic-process-messages-stage-segments-20260521T143706Z/tail3/atlantic-query-check-M-20260522T062831Z
```

分段后的 Atlantic split calldata 已经低于之前卡住的 5000 felt 警戒线：

| segment | initial felts | split total felts | proof artifact | 结论 |
| --- | ---: | ---: | ---: | --- |
| `head2` | 4,583 | 7,937 | ~1.0 MiB | 已通过 Atlantic L2 verification |
| `tail3` | 4,553 | 7,829 | ~1.0 MiB | 已通过 Atlantic L2 verification |

这和 5-message stage 的 `initial = 5,629` felts 形成对比：完整 stage 本地可以证明，但在 Atlantic 当前 L2 verifier path 上会触发 `CALLDATA_TOO_LARGE`；拆成 `tail3 + head2` 后两段都能进入 Atlantic 的 `PROOF_VERIFICATION_ON_L2` 终态。

## Full E2E Round Segment 输入修正

上面的 `head2/tail3` DONE 记录来自 smoke fixture。把同一套 segment 方案接到完整 E2E round 数据时，第一次生成的 full-component 输入暴露出一个链接问题：

```text
source input:
  target/full-component-e2e-20260518T023503Z/inputs/process-messages-boundary-native.json

pre-fix output:
  target/segment-stage-e2e-20260522T065618Z
```

pre-fix 本地 segment commitment 链接结果是：

```text
tail3.new_state_commitment
  0x6f0e80965209462001201fc9a0acfac6798fe2be6537aa8dcf169875593a172

head2.current_state_commitment
  0x7de55796c8af5662f7013c4a16528d57f73f52acdd56cd60074a35add95cef0

result:
  tail3.new != head2.current
```

原因不是 Cairo 执行失败，而是 JS 输入构造里 segment 的中间状态 commitment salt 语义不对：

```text
batch 起点:
  current_state_commitment = hash(current_state_root, current_state_salt)

batch 终点:
  new_state_commitment = hash(new_state_root, new_state_salt)

segment 中间状态:
  current/new commitment 都必须使用 batch 的 new_state_salt
```

修复点：

```text
src/msg/native-process-messages.mjs
  evaluateNativeProcessMessagesBoundarySegment:
    intermediate current_state_commitment 改为使用 newStateSalt

src/msg/native-cairo-input.mjs
  buildNativeCairoProcessMessagesStageSegmentInput:
    覆盖 segment 边界 message core 的 current/new_state_commitment_hash
```

新增测试：

```text
tests/process-messages-state.test.mjs
  links native ProcessMessages stage segment commitments
```

fixed 版完整 E2E segment 本地 artifacts：

```text
output:
  target/segment-stage-e2e-fixed-20260522T070423Z

latest pointer:
  target/segment-stage-e2e-fixed-latest.txt
```

fixed 链接校验：

```text
tail3.current == full.current:
  true

tail3.new == head2.current:
  true

head2.new == full.new:
  true

tail3/head2 bridge commitment:
  0x6f0e80965209462001201fc9a0acfac6798fe2be6537aa8dcf169875593a172

head2 final state commitment:
  0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775
```

fixed 版本地验证：

```bash
scarb build

node --test \
  --test-name-pattern "links native ProcessMessages stage segment commitments" \
  tests/process-messages-state.test.mjs

node --test \
  tests/process-messages-state.test.mjs \
  tests/process-messages.test.mjs \
  tests/atlantic-mock-round-call.test.mjs \
  tests/atlantic-query-bundle.test.mjs

RUN_CAIRO_EXECUTION_TESTS=1 \
node --test \
  --test-name-pattern "stage segment" \
  tests/cairo-execution.test.mjs
```

结果：

```text
process/messages + atlantic related tests:
  32 passed, 0 failed

stage segment Cairo execution test:
  1 passed, 0 failed
```

fixed 版 Atlantic bundle：

| segment | query id | status | program hash | integrity fact hash | 说明 |
| --- | --- | --- | --- | --- | --- |
| `tail3` | `01KS789XFZB1W480HCFHHPBYHW` | `DONE / PROOF_VERIFICATION_ON_L2` | `0x629bd3434387bfd139c424ac566f46cfe9cb7efd7dabef9874c3a6cb96a33fc` | `0x735298b2398cb6926bfc56f631c8bf56997cdea3fe6a58b3238e4de023bd2df` | Completed at `2026-05-22T07:24:10.933Z`。与 pre-fix tail3 fact 相同；pre-fix bug 实际只影响 head2 的 current commitment。 |
| `head2` | `01KS78A9FWD39S2YZWQ8MY0YRA` | `DONE / PROOF_VERIFICATION_ON_L2` | `0x629bd3434387bfd139c424ac566f46cfe9cb7efd7dabef9874c3a6cb96a33fc` | `0x4bab46c4095ad95750f426a843e7688cf1ba6c9e2a2d7ee6049a9a218f1fa78` | Completed at `2026-05-22T07:25:52.573Z`。fixed 后 fact 已变化，后续 wrapper 必须使用这个 fixed head2 fact。 |

Atlantic Console：

```text
tail3:
  https://www.herodotus.cloud/en/atlantic/01KS789XFZB1W480HCFHHPBYHW

head2:
  https://www.herodotus.cloud/en/atlantic/01KS78A9FWD39S2YZWQ8MY0YRA
```

同钱包登录 Herodotus Console 才能查看 query 详情。

pre-fix full E2E 查询也已经提交过，但不应作为本轮 round wrapper 输入使用：

| segment | query id | status | integrity fact hash | 使用结论 |
| --- | --- | --- | --- | --- |
| `tail3` | `01KS77KZB7Z07XV1MYNZX4EDQG` | `IN_PROGRESS / PROOF_GENERATION` | `0x735298b2398cb6926bfc56f631c8bf56997cdea3fe6a58b3238e4de023bd2df` | fact 与 fixed tail3 一致，可以等价复用；但为避免混淆，后续记录优先使用 fixed query id。 |
| `head2` | `01KS77M4HC8V5MEVXBW6GN6F8N` | `IN_PROGRESS / PROOF_GENERATION` | `0x593c16c7dffcc217a07869c671c636801dd6bd32482ce9994023b942641fbf4` | 不可用于本轮 round，因为它的 `current_state_commitment` 没有链接到 tail3 output。 |

fixed bundle 文件：

```text
program file sha256:
  0x5be54b7c0f5e5638cffcaf27e8cd805f6d9b8b1f284a3a7982e35d6498113e00

tail3 input sha256:
  0xdc6c40c0d150d8bcdbaceb234d0a2ff1ed1702e292a5430a687a176fdb40973b

head2 input sha256:
  0x7824575b004f8b6cf898d8f001b909bb0fdf6111f7293e91bb778a4586eee041

program file size:
  6,003,064 bytes

tail3 input:
  898 felts, 27,384 bytes

head2 input:
  898 felts, 26,358 bytes
```

fixed `tail3/head2` 两个 query 已进入 `DONE / PROOF_VERIFICATION_ON_L2`，metadata artifacts 已下载到：

```text
tail3:
  target/segment-stage-e2e-fixed-20260522T070423Z/tail3/atlantic-query-check/artifacts/metadata.json

head2:
  target/segment-stage-e2e-fixed-20260522T070423Z/head2/atlantic-query-check/artifacts/metadata.json
```

已用 fixed `tail3/head2` facts 部署新的 segment round wrapper，并完成
`add-key -> tail3 -> head2 -> tally` 的 Sepolia 调用链路。新的 wrapper/round 配置为：

```text
process_messages_program_hash:
  0x629bd3434387bfd139c424ac566f46cfe9cb7efd7dabef9874c3a6cb96a33fc
```

已执行的业务调用顺序为：

```text
add-new-key fact
tail3 segment fact
head2 segment fact
tally fact
```

这样本轮 round 的 processMessages proof/fact 数从 22 降到 2；完整 add/process/tally 的业务 fact 数从 24 降到 4。

segment wrapper 链上结果：

```text
MockAmaciRound:
  0x05774fb80c7e6bc13221960d5e29d6068594f11b4401bd18449dd21892e51cb5

deploy tx:
  0x0279dcef8f3a6fae6f1a0afe7cdd70bd3e368b9a3fe01507ade187b1cb600186

add-key tx:
  0x01864370f58c1904f9ee0d2cf61fb47bc0d0dee318fa9565a56d4395fc70f7c4

tail3 tx:
  0x027090554a0ae0166f502445687d20c712b806a1d4275a905bc6dcb6243faf05

head2 tx:
  0x06f538c1a83deb17c750bba755ecb428b04909938065c1139318248bfb520e2c

tally tx:
  0x063352207ccb1e09f96dacff26773961f638eb509d222e195c410032ec481147
```

成本记录：

```text
business total:
  0.24960596193123744 STRK

processMessage segment total:
  0.1783379104832663 STRK

deploy:
  0.06212580869448576 STRK

business + deploy:
  0.3117317706257232 STRK
```

最终链上状态：

```text
state commitment:
  0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

tally commitment:
  0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc

keys_added:
  1

message_batches_processed:
  2

total_facts_accepted:
  4

tally_submitted:
  true
```

完整 receipt 和成本明细在：

```text
target/segment-stage-e2e-fixed-20260522T070423Z/chain-segment-wrapper/wrapper-cost-summary.json
```

和原 full component wrapper run 对比：

```text
processMessage facts:
  22 -> 2

total business facts:
  24 -> 4

business wrapper fee:
  0.5908864206 STRK -> 0.2496059619 STRK

processMessage wrapper fee:
  0.5212970546 STRK -> 0.1783379105 STRK
```

已执行的提交命令如下，后续只应在输入或程序 hash 变化后重提，避免重复消费 credit：

```bash
source .env
export ATLANTIC_API_KEY="$ATLANTIC_KEY"
OUT=target/atlantic-process-messages-stage-segments-20260521T143706Z
SHARED_PROGRAM="$OUT/head2/stone-air/process_messages_stage_segment_native_stone.cairo1-run.sierra.json"

npm run export:atlantic-query -- \
  --stone-air-run "$OUT/head2/stone-air/stone-air-run.json" \
  --program-file "$SHARED_PROGRAM" \
  --out-dir "$OUT/head2/atlantic-query" \
  --declared-job-size M \
  --external-id process-messages-stage-head2-native-retry \
  --text
"$OUT/head2/atlantic-query/submit-atlantic-query.sh" \
  | tee "$OUT/head2/submit-response.json"

npm run export:atlantic-query -- \
  --stone-air-run "$OUT/tail3/stone-air/stone-air-run.json" \
  --program-file "$SHARED_PROGRAM" \
  --out-dir "$OUT/tail3/atlantic-query" \
  --declared-job-size M \
  --external-id process-messages-stage-tail3-native-retry \
  --text
"$OUT/tail3/atlantic-query/submit-atlantic-query.sh" \
  | tee "$OUT/tail3/submit-response.json"
```

如果 segment 输入或程序发生变化，应重新生成对应 segment 的 Stone AIR，再复用同一个 `programFile` 提交：

```bash
npm run stone:air:circuit -- \
  --circuit process-messages-stage-head2-native \
  --out-dir <out>/head2/stone-air \
  --skip-cairo1-run

npm run stone:air:circuit -- \
  --circuit process-messages-stage-tail3-native \
  --out-dir <out>/tail3/stone-air \
  --skip-cairo1-run
```

然后用已有 `export:atlantic-query --program-file <shared-programFile>` 分别提交两个 `stone-air-run.json`。如果 Atlantic 返回 DONE，再用 `export:atlantic-round-call` 的 process-messages stage/segment operation 生成 wrapper 调用。

之前本地测试已经说明 native 化后有明显改善：

```text
non-native tally Stone:
  n_steps = 67,108,864
  STARK degree bound = 2^30
  64GB 机器 OOM

native tally Stone:
  n_steps = 131,072
  STARK degree bound = 2^21
  peak RSS ~= 6.2GB
  proof 成功
```

这说明 native 化给 batch 留出了空间，但不能假设 batch5 一定安全，需要实际测量。

## Calldata Size Guard

之前自己提交 Integrity split calldata 时遇到过单笔 calldata 超过 5000 felts 的风险。Atlantic 代提交时，业务合约侧不直接吃这些 calldata，但如果未来自己跑 prover 和自己提交 verifier calldata，这个问题必须工程化处理。

建议引入硬性 guard：

```text
单笔 calldata felts > 5000 时默认 fail
除非显式开启 override
```

每次生成 self-prover artifact 时，都要输出：

```text
proof JSON size
split calldata total felts
initial tx felts
step tx felts
final tx felts
是否超过阈值
```

如果超过阈值，优先选择：

```text
更小 batch size
更多 split step
recursive / bootloaded aggregation
Atlantic/Herodotus 代提交
```

不要直接把超大 calldata 硬推到链上。

## 建议实施顺序

### Phase 1: Wrapper Bundle

先减少 AMACI 业务合约侧调用次数。

做法：

```text
wrapper 一次接收一组 component facts
一次性检查链接关系
一次性更新 round state
```

它不减少 Atlantic proof 数，也不减少 registered fact 数，但可以减少业务 wrapper transaction 数量，工程风险最低。

### Phase 2: Fused Single-Message Proof

实现：

```text
process_message_step_native
```

把每条 message 的 ECDH、decrypt、signature、core state update 合成一个 proof。

目标：

```text
processMessages proof count: 22 -> 7
```

这是进入 batch proof 之前最重要的数据采样点。

### Phase 3: Batch5 Native Proof

实现：

```text
process_messages_batch5_native
```

目标：

```text
processMessages proof count: 7 -> 1~3
```

该阶段必须同时跑：

```text
Scarb/Stwo local proof
Stone AIR/proof
Atlantic query
AMACI wrapper submit
self-prover calldata size report
```

如果 batch5 的 Stone peak RSS 或 calldata 明显超过阈值，则不要强推 batch5，保留 batch1/fused 模式。

### Phase 4: Configurable Batch Size

支持不同执行环境：

```text
batch_size = 1  小机器 / self-prover 保守模式
batch_size = 2  中间模式
batch_size = 5  当前测试 round 模式
```

这样可以根据机器规格、Atlantic 成本和链上成本选择不同 proof 粒度。

### Phase 5: Operation-Level Aggregation

最终目标：

```text
add-key fact
process-messages aggregate fact
tally fact
```

或者更进一步：

```text
round aggregate fact
```

但不建议一开始做 full round proof，因为它会重新引入调试困难、prover 内存不可控和成本不可预测的问题。

## 验收标准

每一个新 proof 粒度都必须记录：

```text
proof/fact 数量变化
Atlantic query id
Atlantic credit cost
Atlantic verification fee
AMACI wrapper submit fee
Stone prover peak RSS
Stone n_steps / degree bound
self-prover split calldata felts
链上 round state 是否与本地 commitment 对齐
```

Milestone 2 的第一阶段成功标准：

```text
processMessages 从 22 个 proof 降到 7 个 proof
E2E round 状态正确
成本低于当前完整 component 流程
Stone/self-prover 指标没有明显恶化到不可接受
```

第二阶段成功标准：

```text
processMessages 从 7 个 proof 进一步降到 1~3 个 proof
batch5 可以被 Atlantic 正常证明和链上消费
self-prover 路径没有超过 calldata guard
```

## 当前结论

短期最稳的优化不是直接做一个巨大 batch proof，而是：

```text
先做 fused single-message proof
再做 batch5 native proof
最后再考虑 aggregate fact
```

这样可以逐步减少 proof/fact 数量，同时保留自建 Stone prover 的可控性。
