# AMACI E2E Round Notes

本文档记录 AMACI native/Atlantic/Starknet E2E round 的实际验证进度、链上交易、Atlantic query、proof verification 费用和 credit 预算。

## Current Status

目前，目标路径已经完成：

```text
add-new-key-native
-> process-message-coord-key-native
-> process-message-ecdh-native x5
-> process-message-decrypt-native x5
-> process-message-signature-native x5
-> process-message-step-core-native x5
-> process-messages-boundary-native
-> tally-native
```

当前状态：

| item | status |
| --- | --- |
| native Cairo circuit implementation | completed |
| Atlantic metadata fact export/submit tooling | completed |
| Atlantic queries for the full component round | `24/24 DONE` |
| Atlantic proof verification tx fee collection | completed |
| AMACI wrapper fact consumption on Sepolia | `29/29 tx succeeded` |
| E2E round final state check | passed |
| cost inventory | completed |

Native circuit family coverage：

| family | native circuits | status |
| --- | --- | --- |
| add key | `add-new-key-native` | implemented, Atlantic path tested, wrapper fact consumption tested |
| processMessage | coord-key, ecdh, decrypt, signature, step-core, boundary | implemented, Atlantic path tested, full component wrapper consumption tested |
| processDeactivate | coord-key, ecdh, decrypt, signature, step-core, boundary | implemented, Atlantic path and wrapper consumption path completed; separate deactivate round cost flow not included in this voting/tallying run |
| tally | `tally-native` | implemented, Atlantic path tested, wrapper fact consumption tested |

本次完整 round 不包含 `process-deactivate` 业务路径，因为这是 `deploy -> add key -> process messages -> tally` 的最小完整投票/计票流程。`process-deactivate` 的 native circuit、wrapper entry 和 Atlantic metadata fact 消费路径已经补齐，但它的实际 round 成本应在包含 deactivate 操作的单独流程里统计。

最终完整 component run 入口：

```text
target/full-component-e2e-20260518T023503Z
```

关键成本摘要：

| scope | cost |
| --- | ---: |
| Atlantic credit budget, runtime quote | `7200 credits` / `$72.00` |
| Atlantic proof verification gas | `95.117322010 STRK` |
| AMACI business fact consumption | `0.590886421 STRK` |
| AMACI wrapper stages, including allowlist | `0.651031217 STRK` |
| deploy + wrapper stages | `0.710952416 STRK` |

## Historical Milestone: Tally

### 目标

验证优化后的 Starknet-native tally Cairo 程序可以通过 Atlantic 生成并验证 proof，由 Atlantic 在 Starknet Sepolia 注册 Integrity fact，然后由 AMACI wrapper/mock round 在链上消费该 fact 并更新 tally commitment。

### 当前结论

`tally` 链路已经在 Starknet Sepolia 上完成闭环：

1. Atlantic query 已完成 proof verification。
2. Integrity fact 已在 Sepolia Satellite/FactRegistry 路径可查询。
3. `MockAmaciRound` 已成功消费 Atlantic metadata-level bootloaded fact。
4. 链上 round 状态已从 `current_tally_commitment = 0x0` 更新为 native tally proof 输出的 `new_tally_commitment`。

### 账户与合约

本地 Sepolia OZ 测试账户：

```text
0x0424d1afc810222071c9eac2cd1b926c0b75d8c92f88d392d53e725f4f08e760
```

账户部署交易：

```text
0x01bf4c4e07cf49df1f6cbefa1e2fc1e93fe5dd3e003a8b95be6d22afbd485e5f
```

`MockAmaciRound` class hash：

```text
0x2eb4ce94c6f6d7ab6cb6870ccc54fd8b0ef252e39e24010afe66a9a36042f0
```

`MockAmaciRound` 本地部署地址：

```text
0x076cfa4a2cfc9127cf4f2955cecf794ef5fd014c0d5e2a91fd01d8aa88e709ba
```

部署交易：

```text
0x0195ee48a1ca084b4c87ff0f5e9558c8d893b362938315ed604f3de37773298e
```

### Atlantic 查询结果

Atlantic query：

```text
01KRSWP39Q5MGPDWX6SE7SNN36
```

Atlantic transaction id：

```text
01KRSWP9P8BANP6X7A9J8S4N46
```

状态：

```text
Status: DONE
Result: PROOF_VERIFICATION_ON_L2
Mock fact: false
Mock proof: false
```

Native tally program hash：

```text
0x26059ab7b74d91be472b4974914eac5156c7883e84a665c9755b67b25c6137d
```

Atlantic metadata program hash：

```text
0x288ba12915c0c7e91df572cf3ed0c9f391aa673cb247c5a208beaa50b668f09
```

Integrity fact hash：

```text
0x105d6c825149ccb9aec7557078fe38b6f1a12163fd99ee68e78e255f33871e3
```

SHARP fact hash：

```text
0x3f3f5260c7a07b7f110224f7b4caa1b73e9dd5934300d6d55efb7e2035efbe8b
```

FactRegistry mode：

```text
satellite
```

Sepolia Satellite address：

```text
0x00421cd95f9ddabdd090db74c9429f257cb6bc1ccc339278d1db1de39156676e
```

本地重建出的匹配模式：

```text
bootloaded:metadata-output:metadata-program:sharp
```

这表示 Atlantic 注册的 fact 不是直接绑定 native tally 12-felt output，而是绑定 metadata-level output；metadata output 内部包含 native tally public output。`MockAmaciRound` 因此使用 `submit_tally_atlantic_metadata_fact` 消费。

### Tally Public State

从 `target/atlantic-query-check/artifacts/metadata.json` 提取：

```text
state_commitment:
0x7a25bed630ce3187c337020533fcbfb30e0e2fe0867ee4ec993d49878526d7f

current_tally_commitment:
0x0

new_tally_commitment:
0xd874fa2f6d97657eec70d5762709797d5ac3c864f8dc20fa805eb13c63565
```

注意：部署 `MockAmaciRound` 时，`initial_tally_commitment` 必须使用 metadata output 中嵌入的 native tally output 的 current tally，也就是 `0x0`。之前误用 new tally 作为 initial tally 会导致链上提交时报：

```text
TALLY_MISMATCH
```

### 本地生成提交命令

拉取 Atlantic query artifacts：

```bash
npm run atlantic:fetch-query -- \
  --query-id 01KRSWP39Q5MGPDWX6SE7SNN36 \
  --out-dir target/atlantic-query-check \
  --download-artifacts \
  --text
```

生成 `MockAmaciRound` submit command：

```bash
export MOCK_ROUND_ADDRESS=0x076cfa4a2cfc9127cf4f2955cecf794ef5fd014c0d5e2a91fd01d8aa88e709ba
export ATLANTIC_METADATA=target/atlantic-query-check/artifacts/metadata.json

npm run export:atlantic-round-call -- \
  --query-result target/atlantic-query-check/atlantic-query-result.json \
  --metadata "$ATLANTIC_METADATA" \
  --wrapper-address "$MOCK_ROUND_ADDRESS" \
  --profile amaci_local_oz \
  --out target/atlantic-round-call.local.json \
  --text
```

执行提交：

```bash
CMD=$(jq -r '.submit.command' target/atlantic-round-call.local.json)
eval "$CMD"
```

提交函数：

```text
submit_tally_atlantic_metadata_fact
```

链上提交交易：

```text
0x005c63700b272d65b6ae5b154953e60f7bdc62f6a4d8762dd8319cdd1c85610d
```

### 链上消费结果

提交后读取 `MockAmaciRound` 状态：

```bash
sncast --profile amaci_local_oz call \
  --contract-address "$MOCK_ROUND_ADDRESS" \
  --function get_state_commitment

sncast --profile amaci_local_oz call \
  --contract-address "$MOCK_ROUND_ADDRESS" \
  --function get_tally_commitment

sncast --profile amaci_local_oz call \
  --contract-address "$MOCK_ROUND_ADDRESS" \
  --function get_tally_submitted

sncast --profile amaci_local_oz call \
  --contract-address "$MOCK_ROUND_ADDRESS" \
  --function get_total_facts_accepted
```

确认结果：

```text
get_state_commitment:
0x7a25bed630ce3187c337020533fcbfb30e0e2fe0867ee4ec993d49878526d7f

get_tally_commitment:
0xd874fa2f6d97657eec70d5762709797d5ac3c864f8dc20fa805eb13c63565

get_tally_submitted:
true

get_total_facts_accepted:
0x1
```

## Native Circuit Wrapper Support

### 当前状态

`MockAmaciRound` 已补齐完整 native AMACI 路径需要的 Atlantic metadata fact 消费入口：

```text
submit_add_new_key_atlantic_metadata_fact
submit_process_messages_atlantic_metadata_fact
submit_process_deactivate_atlantic_metadata_fact
submit_operation_atlantic_metadata_fact
submit_tally_atlantic_metadata_fact
```

`export:atlantic-round-call` 也已经支持按 operation 生成提交命令：

```text
--operation add-new-key
--operation process-messages
--operation process-deactivate
--operation generic
--operation tally
```

这些入口验证的是 Atlantic 当前实际注册的 metadata-level SHARP bootloaded fact：

```text
bootloaded:metadata-output:metadata-program:sharp
```

也就是说，链上不再假设 fact 直接绑定 native circuit public output，而是验证 Atlantic metadata output 的 registered fact，同时在 metadata output 内扫描并约束对应 native circuit 的 public output header 和关键状态字段。

### Operation 约束

`add-new-key`：

- 校验 metadata 中的 child program hash 等于 round 配置的 `add_new_key_program_hash`。
- 扫描 `AMACI_ADD_KEY_NATIVE` public output。
- 绑定 `key_nullifier`，防止重复 add key。
- 当前 native add-key output 不直接包含 new state commitment，因此 mock round 仍由调用参数提供 `new_state_commitment`，用于流程成本评估。

`process-messages`：

- 扫描 `AMACI_PROCESS_MSG_NATIVE` public output。
- 约束 current state commitment、new state commitment、current deactivate commitment。
- 成功后更新 round state commitment。

`process-deactivate`：

- 扫描 `AMACI_PROCESS_DEACT_NATIVE` public output。
- 约束 current deactivate commitment 和 new deactivate commitment。
- 同时要求调用参数中的 current state commitment 等于合约当前 state commitment。
- 成功后更新 deactivate commitment。

`generic`：

- 用于先消费 split helper/component 级 metadata fact。
- 只验证 metadata fact、child program hash allowlist 和 fact registry 状态，不更新 round 主状态。

### 本地验证

新增路径已通过：

```bash
node --test tests/atlantic-mock-round-call.test.mjs
npm run test:contracts
npm test
```

关键结果：

```text
atlantic-mock-round-call tests: 7 passed
contracts tests: 38 passed
npm test: 158 tests, 147 passed, 11 skipped, 0 failed
```

## Historical Milestone: Minimal Round Prototype

目标流程先压到最小：

```text
deploy MockAmaciRound
  -> submit add-new-key Atlantic metadata fact
  -> submit process-messages Atlantic metadata fact
  -> submit tally Atlantic metadata fact
```

注意：不能直接把历史上已经 DONE 的 `process-messages-boundary-native` 和 `tally-native` 随便串起来。当前已下载的一组历史数据里：

```text
process_messages.new_state_commitment =
0xd7d4fc4256a6959cfcce12444a612a59e1b25c984eef42a81b81f9f3d35f2c

tally.state_commitment =
0x7a25bed630ce3187c337020533fcbfb30e0e2fe0867ee4ec993d49878526d7f
```

这两个值不相等，所以如果强行按 round 流程提交，`tally` 会被 `STATE_MISMATCH` 拒绝。

为避免继续误用不连续 proof，新增了最小 native round fixture 生成器：

```bash
npm run write:minimal-round-fixture -- \
  --out-dir target/minimal-native-round-$(date -u +%Y%m%dT%H%M%SZ) \
  --text
```

本次生成路径：

```text
target/minimal-native-round-20260517T153258Z/process-messages-boundary-native.json
target/minimal-native-round-20260517T153258Z/tally-native.json
target/minimal-native-round-20260517T153258Z/chain.json
```

关键状态：

```text
initial_state_commitment =
0x1e717935e50b681995682b2d0c5e3706756ac59395d910debf166fc9f3f25e5

process_messages.new_state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

tally.state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

initial_tally_commitment = 0
final_tally_commitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc
```

准备链路验证：

```bash
npm run prepare:circuit -- \
  --circuit process-messages-boundary-native \
  target/minimal-native-round-20260517T153258Z/process-messages-boundary-native.json \
  --out target/minimal-native-round-20260517T153258Z/process-messages-boundary-native.prepared.json

npm run prepare:circuit -- \
  --circuit tally-native \
  target/minimal-native-round-20260517T153258Z/tally-native.json \
  --out target/minimal-native-round-20260517T153258Z/tally-native.prepared.json
```

该最小流程后续已升级为 2026-05-18 的完整 component run：不再只提交 boundary/tally，而是把 processMessage 的 coord-key、ecdh、decrypt、signature、step-core、boundary 全部作为独立 Atlantic fact 逐个提交并由 wrapper 消费。

## Complete Round Cost Run 2026-05-17

本节开始记录完整 round 成本测试。目标不是重新证明协议生产安全性，而是用最小连续数据跑通：

```text
deploy MockAmaciRound
  -> submit add-new-key fact
  -> submit process-messages fact
  -> submit tally fact
```

本次运行目录：

```text
target/e2e-round-20260517T154056Z
```

manifest：

```text
target/e2e-round-20260517T154056Z/round-manifest.json
```

输入文件：

```text
target/e2e-round-20260517T154056Z/inputs/process-messages-boundary-native.json
target/e2e-round-20260517T154056Z/inputs/tally-native.json
target/e2e-round-20260517T154056Z/inputs/chain.json
```

本次 round 的状态承接关系：

```text
initial_state_commitment =
0x1e717935e50b681995682b2d0c5e3706756ac59395d910debf166fc9f3f25e5

process_messages.new_state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

tally.state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

initial_tally_commitment = 0x0

final_tally_commitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc
```

### Atlantic Submissions

`add-new-key-native` 暂时复用已完成的 Atlantic fact：

| stage | circuit | Atlantic query id | status | tx id | program hash | Integrity fact hash |
| --- | --- | --- | --- | --- | --- | --- |
| add key | `add-new-key-native` | `01KRTRTT287VVMPJ8KA8DXB8WN` | `DONE` | `01KRTRV0HAZ0GHESCFQAERSYV2` | `0x6abd121b6593681a0d451b900ce5ccbde47eb885eef60bdfc65b292b9006039` | `0x2565909fcfe0c955f6de46fbc85d2934ddb4814947317bc01242c543097ad58` |

复用原因：当前 native add-key output 不直接绑定 `new_state_commitment`，mock round 原型允许提交时传入 `new_state_commitment`。本次完整 round 中这个值会设置为：

```text
0x1e717935e50b681995682b2d0c5e3706756ac59395d910debf166fc9f3f25e5
```

本次新提交到 Atlantic 的电路：

| stage | circuit | Atlantic query id | current status | current step | tx id | program hash | Integrity fact hash |
| --- | --- | --- | --- | --- | --- | --- | --- |
| process messages | `process-messages-boundary-native` | `01KRV9KRY482BYETEFYH1BXEF7` | `DONE` | `PROOF_VERIFICATION` | `01KRV9KZ9SFRA8EP0FBD7FTBV2` | `0x4b710be8156dde20f322335797c947bc7d1fe362d56139c5c8f8f502231ce0f` | `0x2ec4d6d10fbdacecfe8a5a4b77cf2aad1cf242d48cbf2a8e83cbd963d5be478` |
| tally | `tally-native` | `01KRV9KV7N5AF59XG905KN448A` | `DONE` | `PROOF_VERIFICATION` | `01KRV9M6P0DNR778KTN28BTJ1K` | `0x46f4e3ce5ef38dc13944476010804d52c8c24afca094c24b6b0a608d8591425` | `0x1391ebda0a7cfda9736eb6bf1f1fbaf4d7b6be14fa6a3ff69d8ac2766ad3011` |

Atlantic console：

```text
https://www.herodotus.cloud/en/atlantic/01KRTRTT287VVMPJ8KA8DXB8WN
https://www.herodotus.cloud/en/atlantic/01KRV9KRY482BYETEFYH1BXEF7
https://www.herodotus.cloud/en/atlantic/01KRV9KV7N5AF59XG905KN448A
```

提交结果：

```text
credit failures: none
not submitted because of credit: none
```

状态快照：

```text
target/e2e-round-20260517T154056Z/add-new-key-native/atlantic-status/final-query-summary.json
target/e2e-round-20260517T154056Z/process-messages-boundary-native/atlantic-status/final-query-summary.json
target/e2e-round-20260517T154056Z/tally-native/atlantic-status/final-query-summary.json
```

artifacts 已下载：

```text
target/e2e-round-20260517T154056Z/add-new-key-native/atlantic-status/artifacts
target/e2e-round-20260517T154056Z/process-messages-boundary-native/atlantic-status/artifacts
target/e2e-round-20260517T154056Z/tally-native/atlantic-status/artifacts
```

完成时间：

```text
add-new-key-native: 2026-05-17T11:28:53.258Z
process-messages-boundary-native: 2026-05-17T15:48:26.882Z
tally-native: 2026-05-17T15:49:37.317Z
```

本地 metadata fact 重建检查：

| circuit | operation | candidate matches | selected mode |
| --- | --- | --- | --- |
| `add-new-key-native` | `addNewKey` | `1` | `bootloaded:metadata-output:metadata-program:sharp` |
| `process-messages-boundary-native` | `processMessages` | `1` | `bootloaded:metadata-output:metadata-program:sharp` |
| `tally-native` | `tally` | `1` | `bootloaded:metadata-output:metadata-program:sharp` |

检查产物：

```text
target/e2e-round-20260517T154056Z/add-new-key-native/atlantic-round-call.check.json
target/e2e-round-20260517T154056Z/process-messages-boundary-native/atlantic-round-call.check.json
target/e2e-round-20260517T154056Z/tally-native/atlantic-round-call.check.json
```

### Starknet Wrapper Execution

本次使用账户：

```text
amaci_local_oz
0x0424d1afc810222071c9eac2cd1b926c0b75d8c92f88d392d53e725f4f08e760
```

`MockAmaciRound` class hash：

```text
0x07fee61ef52e9d2c1fdce0f72629d824c654e3851193f89144092057b4387dad
```

declare tx：

```text
0x03ee2784e84fe6e3306afa8fed4022b8e4651bf0e128d2f3fd7ff985413ebb87
```

本次 round address：

```text
0x061e761cb99d62170de51e4daf3725b43a1e4e85682fe31e27e1caa667e127e6
```

deploy tx：

```text
0x01b6f02893430f9e82123b725c1ae1644601d7d91d842bc5dc68b4e9d7b03b97
```

constructor 关键参数：

```text
initial_state_commitment = 0x0
initial_deactivate_commitment =
0x2838ad41c0aecc7fce6b9df78cdd4cbb485f329fd63dd7c44adea2f8583de94
initial_tally_commitment = 0x0
```

这里故意把 `initial_state_commitment` 设为 `0x0`，让 add-key 这笔把 state 更新成本次 process-messages proof 需要的：

```text
0x1e717935e50b681995682b2d0c5e3706756ac59395d910debf166fc9f3f25e5
```

链上提交顺序和结果：

| stage | function | tx | actual fee | l2 gas | result |
| --- | --- | --- | --- | --- | --- |
| add key | `submit_add_new_key_atlantic_metadata_fact` | `0x07e8c4b9cfc6798028685ea3c706cbad8bfc18a277144c1a526e49fbb3c700b3` | `38103085104898816 fri` (~`0.0381030851 STRK`) | `4762880` | succeeded |
| process messages | `submit_process_messages_atlantic_metadata_fact` | `0x04e623fcf5793a307496b307ae5dfccedb1d06aaa6341ce09c85fa377d966ecf` | `27856032877787072 fri` (~`0.0278560329 STRK`) | `3482000` | succeeded |
| tally | `submit_tally_atlantic_metadata_fact` | `0x067317b9d20fdaf630ae69ed9fed6a57601aa6f1df14184d6ac413bfbbd41545` | `31481635708874880 fri` (~`0.0314816357 STRK`) | `3935200` | succeeded |

部署和 round 操作成本：

| scope | actual fee |
| --- | --- |
| wrapper calls only: add-key + process-messages + tally | `97440753691560768 fri` (~`0.0974407537 STRK`) |
| deploy + wrapper calls | `160891107585579456 fri` (~`0.1608911076 STRK`) |
| declare + deploy + wrapper calls | `9474176242232225344 fri` (~`9.4741762422 STRK`) |

注意：declare 成本很高，不应该计入每个 round 的常规成本。后续复用已声明 class 时，round 成本更接近 `deploy + wrapper calls`；如果未来 round 合约也可复用，单 round 操作成本更接近 `wrapper calls only`。

最终状态读取：

```text
get_state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

get_deactivate_commitment =
0x2838ad41c0aecc7fce6b9df78cdd4cbb485f329fd63dd7c44adea2f8583de94

get_tally_commitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc

get_keys_added = 1
get_message_batches_processed = 1
get_total_facts_accepted = 3
get_tally_submitted = true
```

本地记录：

```text
target/e2e-round-20260517T154056Z/chain/e2e-cost-summary.json
target/e2e-round-20260517T154056Z/chain/final-round-state.txt
target/e2e-round-20260517T154056Z/chain/receipts
```

Atlantic proof verification fee：

```text
已在 2026-05-18 的完整 component run 中补齐。
```

补齐方法是读取 Atlantic 官方 jobs API 中的 `PROOF_VERIFICATION.context.*.transactionHash`，再通过 Starknet RPC 逐笔查询 receipt 的 `actual_fee`。完整结果见 `Atlantic Proof Verification Fees` 节。

### Full Round Atlantic Cost Inventory

2026-05-18 追加整理了一份不重复提交的完整 round proof 成本库存，只覆盖当前要评估的三段：

```text
add new key
processMessage
tally
```

`process_deactivate` 不在这次 round 成本范围内。

本地结构化记录：

```text
target/atlantic-wrapper-inventory/round-production-cost-inventory.json
target/atlantic-wrapper-inventory/round-production-cost-inventory.md
```

2026-05-18 后，成本库存已经升级为完整统计：

- Atlantic proof verification gas：通过 Atlantic jobs API + Starknet receipt 汇总。
- Atlantic credit 预算：通过实际 x402 quote 和官方 pricing 文档公式分别估算。
- AMACI wrapper consumption gas：通过本地账户实际提交的 Starknet receipts 汇总。

完整拆分模型下，小样本 round 的 proof job 展开如下：

| flow | representative Atlantic queries | expanded proof jobs | status | job size |
| --- | ---: | ---: | --- | --- |
| add new key | `1` | `1` | `DONE` | `S` |
| processMessage | `6` | `22` | `DONE` | `S` |
| tally | `1` | `1` | `DONE` | `S` |
| total | `8` | `24` | `DONE` | `S` |

`processMessage` 的 `22` 个 proof jobs 来自：

```text
boundary: 1
coord-key: 1
ecdh: 5
decrypt: 5
signature: 5
step-core: 5
```

也就是当前 5-message 小样本下的 `2 + 4N` 模型。未来如果消息数是 `N`，在没有 aggregate proof 前，processMessage 的拆分 proof jobs 约为 `2 + 4N`。

已完成的 Atlantic query 记录：

| flow | circuit | multiplicity | query id | Atlantic tx id | Integrity fact hash |
| --- | --- | ---: | --- | --- | --- |
| add new key | `add-new-key-native` | `1` | `01KRTRTT287VVMPJ8KA8DXB8WN` | `01KRTRV0HAZ0GHESCFQAERSYV2` | `0x2565909fcfe0c955f6de46fbc85d2934ddb4814947317bc01242c543097ad58` |
| processMessage | `process-messages-boundary-native` | `1` | `01KRV9KRY482BYETEFYH1BXEF7` | `01KRV9KZ9SFRA8EP0FBD7FTBV2` | `0x2ec4d6d10fbdacecfe8a5a4b77cf2aad1cf242d48cbf2a8e83cbd963d5be478` |
| processMessage | `process-message-coord-key-native` | `1` | `01KRV3TFE3MCJD6JRS2F837EVA` | `01KRV3TNX71KD54JH97FB49S0E` | `0x302188e23e95def7d9f6d0ec9905c83fab4b312ead60c205285ced9964e6768` |
| processMessage | `process-message-ecdh-native` | `5` | `01KRV3TJ1YTQJY0934Y6F28FQ7` | `01KRV3TX65AE0EHEXT1TXSF08Q` | `0x65fc3d58bbdd1c91ba3b535545bd0795fa3114985aec1f57a0f025c6b794b7c` |
| processMessage | `process-message-decrypt-native` | `5` | `01KRV3TNG5KSPWMGT8HTA8HS9D` | `01KRV3TVV2AD3KT691VNAZ7C2E` | `0x5b0ef3f6377d17b52af19b831a327aaea61953bdbbd5cba8db897b70952f6aa` |
| processMessage | `process-message-signature-native` | `5` | `01KRV3TQXJT4W43XD61R2QWM9H` | `01KRV3TXYXRSY7FE3XF11ZW8ZJ` | `0x6b89d1c7e0660a8a44e94e1640b35c3b3ff508551e19aeba885bd19787a3d2e` |
| processMessage | `process-message-step-core-native` | `5` | `01KRV5M4AEH33XMDS68ZXQSBCW` | `01KRV5MHZRRR7DTTQ5M88V4EJA` | `0x56c16dbf4f7888ce6c9b6158054783007d5d7cc3a34c9d4f6a26252283e0a9d` |
| tally | `tally-native` | `1` | `01KRV9KV7N5AF59XG905KN448A` | `01KRV9M6P0DNR778KTN28BTJ1K` | `0x1391ebda0a7cfda9736eb6bf1f1fbaf4d7b6be14fa6a3ff69d8ac2766ad3011` |

对应 Herodotus console URL 格式：

```text
https://www.herodotus.cloud/en/atlantic/<query-id>
```

历史上最小 linked flow 的 Starknet wrapper 调用成本如下：

| scope | actual fee |
| --- | --- |
| add-key + process-messages + tally wrapper calls | `97440753691560768 fri` (~`0.0974407537 STRK`) |
| deploy + wrapper calls | `160891107585579456 fri` (~`0.1608911076 STRK`) |
| declare + deploy + wrapper calls | `9474176242232225344 fri` (~`9.4741762422 STRK`) |

注意：上面这三行是 2026-05-17 的最小 linked flow 成本，不是最终完整 component 成本。完整 component 成本见 2026-05-18 的 `Full Component Wrapper Execution`。

完整小电路 wrapper 成本状态：

```text
status = measured_onchain
```

2026-05-17 时本地只有最小 linked flow 的 3 笔 wrapper receipt：

```text
target/e2e-round-20260517T154056Z/chain/receipts/add-key.receipt.json
target/e2e-round-20260517T154056Z/chain/receipts/process-messages.receipt.json
target/e2e-round-20260517T154056Z/chain/receipts/tally.receipt.json
```

2026-05-18 已补齐以下完整 processMessage 小电路通过 wrapper 逐个提交后的 Starknet receipt：

| wrapper submit | multiplicity in 5-message round |
| --- | ---: |
| `process-message-coord-key-native` | `1` |
| `process-message-ecdh-native` | `5` |
| `process-message-decrypt-native` | `5` |
| `process-message-signature-native` | `5` |
| `process-message-step-core-native` | `5` |

完整 wrapper 成本已经通过实际 invoke 和 receipt 汇总，结构化记录在：

```text
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-execution-results.json
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-cost-summary.json
```

### Scope And Remaining Production Work

这次验证证明完整 component round 可以通过 Atlantic 路径上链并被 AMACI mock wrapper 消费。当前仍是 E2E 成本评估和流程验证用的 mock round，不是生产 AMACI 合约。

生产化前还需要继续做：

1. 把 `MockAmaciRound` 的流程约束迁移成生产 AMACI 合约接口。
2. 确定 metadata program hash、child program hash、verifier config 的生产级 allowlist/升级策略。
3. 把 add-key、processMessage、processDeactivate、tally 的状态机和权限模型接入真实 round 生命周期。
4. 做包含 `process-deactivate` 的单独 round/cost flow，因为本轮最小投票/计票 round 没有触发 deactivate。
5. 设计 aggregate proof 或 recursive fact 聚合方案，减少当前 `2 + 4N` processMessage 拆分模型带来的 query 数和 verification 成本。

### Full Component E2E Run 2026-05-18

本轮开始按完整 component 口径串联：

```text
deploy round
-> add-new-key-native
-> process-message-coord-key-native
-> process-message-ecdh-native x5
-> process-message-decrypt-native x5
-> process-message-signature-native x5
-> process-message-step-core-native x5
-> process-messages-boundary-native
-> tally-native
```

本轮使用同一份 native fixture 生成 processMessage component、boundary 和 tally 输入，避免复用历史中状态不连续的 proof。精确复用规则是：

```text
programFile sha256 和 inputFile sha256 必须同时匹配已 DONE 的 Atlantic query
```

比较结果：当前优化后的代码生成的 24 个 bundle 没有任何一个能精确复用旧 DONE query。因此本轮按当前代码重新提交。

本地记录：

```text
target/full-component-e2e-20260518T023503Z/inputs
target/full-component-e2e-20260518T023503Z/bundle-reuse-analysis.json
target/full-component-e2e-20260518T023503Z/atlantic-submissions.json
target/full-component-e2e-20260518T023503Z/full-component-e2e-manifest.json
target/full-component-e2e-20260518T023503Z/full-component-e2e-status.md
target/full-component-e2e-20260518T023503Z/poll-submitted.sh
target/full-component-e2e-20260518T023503Z/resubmit-credit-blocked.sh
```

最终提交状态（2026-05-18 11:55 Asia/Shanghai）：

| status | count |
| --- | ---: |
| total bundles | `24` |
| submitted | `24` |
| done | `24` |
| in progress | `0` |
| failed | `0` |
| blocked by credits | `0` |

完整 Atlantic query、transaction id、program hash、Integrity fact hash 记录在：

```text
target/full-component-e2e-20260518T023503Z/atlantic-submissions.json
target/full-component-e2e-20260518T023503Z/full-component-e2e-status.md
```

本轮补 key 后成功补提并完成了之前 credit-blocked 的 10 个 query：

```text
process-message-signature-native-2: 01KRWH1Z0VE3X9HBA7Y97KEZYH
process-message-signature-native-3: 01KRWH20JK309DY0K6W45TZNY9
process-message-signature-native-4: 01KRWH230DNQTQTFD7RVS3SF1A
process-message-step-core-native-0: 01KRWH24FQ8GMCYRQFQXKSZS4H
process-message-step-core-native-1: 01KRWH27MGCT0Y8C6A3DZY332R
process-message-step-core-native-2: 01KRWH2AW97HJJSVYVK59DYG72
process-message-step-core-native-3: 01KRWH2E3P570YYQ6PA302Z4RE
process-message-step-core-native-4: 01KRWH2J73BS432F0TWQTAXSBN
process-messages-boundary-native: 01KRWH2N5YDNB31AH3CHBEMMJP
tally-native: 01KRWH2PHX0E6A02GJE82EB94A
```

对应 Herodotus console URL 格式：

```text
https://www.herodotus.cloud/en/atlantic/<query-id>
```

### Full Component Business Data

这一节把本轮实际测试的业务数据按 round 流程拆开说明，方便不熟悉电路的人理解这次到底验证了什么。

本轮是一个小样本 round：

| item | value |
| --- | ---: |
| round / poll id | `77` |
| sign-up 上限 / `numSignUps` | `20` |
| vote option 数量 | `5` |
| state leaf 数量 | `5` |
| message batch 数量 | `1` |
| 每个 batch 的 vote message 数量 | `5` |
| 每条 encrypted message 宽度 | `10 felts` |
| deactivate 操作数量 | `0` |

业务流程如下：

```text
deploy round
-> consume 1 add-new-key proof
-> consume 5 vote messages through processMessage component proofs
-> consume 1 process-messages boundary proof
-> consume 1 tally proof
```

注意：这轮是 `MockAmaciRound` 的连贯成本/链路验证 fixture。它证明了 add-key fact、processMessage component facts、boundary fact 和 tally fact 可以按状态承接被链上 wrapper 消费；但它还不是生产级“同一个真实用户 add key 后立即用这个新 key 投票”的完整用户语义 fixture。当前 native add-key output 不直接绑定 `new_state_commitment`，因此 mock wrapper 在调用时把后续 processMessage 需要的 linked state commitment 作为 calldata 传入。生产化时还需要把这部分接入真实 AMACI round 状态机。

Round 创建时的初始状态：

```text
initial_state_commitment =
0x1e717935e50b681995682b2d0c5e3706756ac59395d910debf166fc9f3f25e5

initial_deactivate_commitment =
0x2838ad41c0aecc7fce6b9df78cdd4cbb485f329fd63dd7c44adea2f8583de94

initial_tally_commitment =
0x0
```

Add-key 阶段实际消费了 1 个 native add-key fact：

| field | value |
| --- | --- |
| `pollId` | `77` |
| `oldPrivateKey` | `7` |
| `deactivateIndex` | `42` |
| `newPubKey.x` | `2645068156583085050795409844793952496341966587935372213947442411891928926825` |
| `newPubKey.y` | `18721023485287444620535873833099074300132272004358512346950884094158923211889` |
| key nullifier | `0x141458e3d328e81d5d46cade4f001a45bec21b12387be7d256ec22a8beb84484` |

Add-key 之后，链上 wrapper 的业务计数变成：

```text
keysAdded = 1
```

随后进入 processMessage。这个 batch 里有 5 条 vote message，全部是有效消息：

```text
isValid = 1
isSignatureValid = 1
isDecryptionActive = 1
expectedPollId = 77
coordPrivKey = 5
```

这 5 条消息的业务含义如下：

| message | state index | vote option | vote weight change | nonce | command new pubkey | new balance |
| ---: | ---: | ---: | --- | ---: | --- | ---: |
| `0` | `0` | `0` | `1 -> 2` | `11` | `(500, 600)` | `1000` |
| `1` | `1` | `1` | `3 -> 4` | `12` | `(501, 601)` | `1096` |
| `2` | `2` | `2` | `5 -> 6` | `13` | `(502, 602)` | `1192` |
| `3` | `3` | `3` | `7 -> 8` | `14` | `(503, 603)` | `1288` |
| `4` | `4` | `4` | `9 -> 10` | `15` | `(504, 604)` | `1384` |

换成直观语言：这一批里有 5 个 state leaf 分别提交了 5 条 vote command，每条 command 指向一个不同的 vote option，并把对应用户的 vote weight 更新到新的值。由于当前是 quadratic-cost fixture，balance 也会随 vote weight 更新而变化。

processMessage 阶段不是一个大 proof，而是完整拆成 component proof：

| component | count | role |
| --- | ---: | --- |
| `process-message-coord-key-native` | `1` | 约束协调者 key / batch 级公共参数 |
| `process-message-ecdh-native` | `5` | 每条 message 的 ECDH/shared-key 检查 |
| `process-message-decrypt-native` | `5` | 每条 message 的 decrypt/command 解密检查 |
| `process-message-signature-native` | `5` | 每条 command 的签名检查 |
| `process-message-step-core-native` | `5` | 每条 message 的状态转移核心检查 |
| `process-messages-boundary-native` | `1` | 约束整个 batch 的起止状态承接 |

所以本轮 processMessage 总 proof job 数是：

```text
1 + 5 + 5 + 5 + 5 + 1 = 22
```

也就是当前 `N = 5` 时的 `2 + 4N` 模型。processMessage 完成后，round state commitment 更新为：

```text
new_state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775
```

链上 wrapper 的业务计数变成：

```text
messageBatchesProcessed = 1
totalFactsAccepted = 23
```

这里的 `23` 包含：

```text
1 add-key fact
+ 21 processMessage component/helper facts consumed before boundary
+ 1 process-messages boundary fact
```

最后进入 tally。tally 使用的 state commitment 必须等于 processMessage 后的新状态：

```text
tally.state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775
```

tally 输入里的 vote matrix 是 5 个 state leaf 对 5 个 vote options 的投票权重矩阵：

```text
[
  [2, 2, 3, 4, 5],
  [2, 4, 4, 5, 6],
  [3, 4, 6, 6, 7],
  [4, 5, 6, 8, 8],
  [5, 6, 7, 8, 10]
]
```

tally 的正确性验证方式很直接：按列求和，得到 5 个 vote option 的最终结果。

```text
option 0: 2 + 2 + 3 + 4 + 5  = 16
option 1: 2 + 4 + 4 + 5 + 6  = 21
option 2: 3 + 4 + 6 + 6 + 7  = 26
option 3: 4 + 5 + 6 + 8 + 8  = 31
option 4: 5 + 6 + 7 + 8 + 10 = 36
```

因此本轮 tally result 是：

```text
[16, 21, 26, 31, 36]
```

tally commitment 从空结果状态更新为：

```text
current_tally_commitment =
0x0

new_tally_commitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc
```

tally fact 被 wrapper 成功消费后，最终链上状态变成：

```text
keysAdded = 1
messageBatchesProcessed = 1
deactivateBatchesProcessed = 0
totalFactsAccepted = 24
tallySubmitted = true

stateCommitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

deactivateCommitment =
0x2838ad41c0aecc7fce6b9df78cdd4cbb485f329fd63dd7c44adea2f8583de94

tallyCommitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc
```

这就是本轮“业务数据演变”的核心：1 个 round、1 次 add key、1 个包含 5 条 vote message 的 batch、22 个 processMessage proof jobs、1 次 tally，最终从 5x5 vote matrix 得到 `[16, 21, 26, 31, 36]`，并在链上 wrapper 状态里确认 tally commitment 已更新。

### Full Component Wrapper Execution

本轮使用 Sepolia 账户：

```text
amaci_local_oz
0x0424d1afc810222071c9eac2cd1b926c0b75d8c92f88d392d53e725f4f08e760
```

复用已声明的 `MockAmaciRound` class hash：

```text
0x07fee61ef52e9d2c1fdce0f72629d824c654e3851193f89144092057b4387dad
```

本轮部署的 wrapper / round address：

```text
0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262
```

链上查看入口：

| item | value |
| --- | --- |
| Sepolia account | [0x0424d1afc810222071c9eac2cd1b926c0b75d8c92f88d392d53e725f4f08e760](https://sepolia.voyager.online/contract/0x0424d1afc810222071c9eac2cd1b926c0b75d8c92f88d392d53e725f4f08e760) |
| MockAmaciRound / round state contract | [0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262) |
| deploy tx | [0x0757cc62acbf464d8c94b4b1a3d78d8174ed4e1bca61f446726d889a51533a5a](https://sepolia.voyager.online/tx/0x0757cc62acbf464d8c94b4b1a3d78d8174ed4e1bca61f446726d889a51533a5a) |
| add-key wrapper submit tx | [0x07add36b0c8df227b5740ef238e2a6761709919c435810f562a0162905f99170](https://sepolia.voyager.online/tx/0x07add36b0c8df227b5740ef238e2a6761709919c435810f562a0162905f99170) |
| process-messages boundary wrapper submit tx | [0x01253237213d436d1f9d0312896e79cccb6c03605652e38e89309ad796095b9f](https://sepolia.voyager.online/tx/0x01253237213d436d1f9d0312896e79cccb6c03605652e38e89309ad796095b9f) |
| tally wrapper submit tx | [0x0097d44d00d4124454df39b5108924e8bbb873236879fe5df1bc3d16726a8049](https://sepolia.voyager.online/tx/0x0097d44d00d4124454df39b5108924e8bbb873236879fe5df1bc3d16726a8049) |

链上状态最终落在 `MockAmaciRound / round state contract` 这个地址。Explorer 可以直接查看合约和交易；精确的 getter 读取结果记录在下方 `最终链上状态`，完整 29 笔 wrapper 交易、receipt 和 gas 记录在：

```text
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-execution-results.json
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-cost-summary.json
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/receipts
```

本地数据和链上状态可以这样对照：

| what to check | local source | local value | on-chain source | on-chain value |
| --- | --- | --- | --- | --- |
| processMessage 后的 state commitment | `target/full-component-e2e-20260518T023503Z/inputs/chain.json` -> `processMessagesNewStateCommitment` | `0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775` | `MockAmaciRound.get_state_commitment()` on [round contract](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262) | `0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775` |
| deactivate commitment | `target/full-component-e2e-20260518T023503Z/inputs/chain.json` -> `initialDeactivateCommitment` | `0x2838ad41c0aecc7fce6b9df78cdd4cbb485f329fd63dd7c44adea2f8583de94` | `MockAmaciRound.get_deactivate_commitment()` on [round contract](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262) | `0x2838ad41c0aecc7fce6b9df78cdd4cbb485f329fd63dd7c44adea2f8583de94` |
| tally commitment | `target/full-component-e2e-20260518T023503Z/inputs/tally-native.json` -> `newTallyCommitment` | `0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc` | `MockAmaciRound.get_tally_commitment()` on [round contract](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262) | `0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc` |
| add-key count | `target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-cost-summary.json` -> `finalState.keysAdded` | `1` | `MockAmaciRound.get_keys_added()` on [round contract](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262) | `0x1` |
| processed message batch count | `target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-cost-summary.json` -> `finalState.messageBatchesProcessed` | `1` | `MockAmaciRound.get_message_batches_processed()` on [round contract](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262) | `0x1` |
| accepted fact count | `target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-cost-summary.json` -> `finalState.totalFactsAccepted` | `24` | `MockAmaciRound.get_total_facts_accepted()` on [round contract](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262) | `0x18` |
| tally submitted flag | `target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-cost-summary.json` -> `finalState.tallySubmitted` | `true` | `MockAmaciRound.get_tally_submitted()` on [round contract](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262) | `true` |

本地 commitment 的计算来源：

```text
fixture entry:
  tools/write-full-round-fixture.mjs

round fixture builder:
  src/fixtures/small-amaci-fixtures.mjs

native processMessage evaluator:
  src/msg/native-process-messages.mjs

native tally evaluator:
  src/tally/native-tally-votes.mjs
```

这些 commitment 是 JS evaluator 在生成 fixture 时先算出来的，但链上不是信任 JS 的结果。JS 侧使用 `starknet.js` 的 Starknet Poseidon，即 `hash.computePoseidonHashOnElements`，和 Cairo native 程序里的 `PoseidonTrait` 对齐。关键公式是：

```text
processMessages.currentStateCommitment = Poseidon(currentStateRoot, currentStateSalt)
processMessages.newStateCommitment     = Poseidon(newStateRoot, newStateSalt)
deactivateCommitment                   = Poseidon(activeStateRoot, deactivateRoot)

tally.stateCommitment                  = Poseidon(stateRoot, stateSalt)
tally.currentTallyCommitment           = 0 for first batch, otherwise Poseidon(currentResultsRoot, currentResultsRootSalt)
tally.newTallyCommitment               = Poseidon(newResultsRoot, newResultsRootSalt)
```

然后这些值进入 Cairo program input/public output。Cairo proof 会重新计算并 assert 同一个结果，Atlantic/Integrity 负责验证 proof 并注册 fact，最后 `MockAmaciRound` 只接受已经注册的 fact，并把 proof public output 里的 commitment 写入 round 状态。所以校验链路是：

```text
local fixture data
  -> JS evaluator computes expected public fields
  -> Cairo native program recomputes and constrains those fields in proof
  -> Atlantic verifies proof and registers Integrity fact on Starknet
  -> MockAmaciRound checks registered fact, program hash, verifier config/security bits, and public output
  -> MockAmaciRound updates state/tally commitment
  -> chain getter returns the same commitment as local fixture
```

明文票数不直接存链上。本轮明文 tally 数据在：

```text
target/full-component-e2e-20260518T023503Z/inputs/tally-native.json
```

其中 `votes` 是：

```text
[
  [2, 2, 3, 4, 5],
  [2, 4, 4, 5, 6],
  [3, 4, 6, 6, 7],
  [4, 5, 6, 8, 8],
  [5, 6, 7, 8, 10]
]
```

按列求和得到明文结果：

```text
[16, 21, 26, 31, 36]
```

这组明文结果被 tally proof 约束进 `newTallyCommitment`，然后链上 wrapper 只保存 commitment：

```text
local newTallyCommitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc

chain get_tally_commitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc
```

因此对照关系是：本地明文票数 `[16, 21, 26, 31, 36]` 生成并约束到本地 `newTallyCommitment`，链上通过 [tally wrapper submit tx](https://sepolia.voyager.online/tx/0x0097d44d00d4124454df39b5108924e8bbb873236879fe5df1bc3d16726a8049) 验证 Atlantic registered fact 后，把同一个 commitment 写入 [round contract](https://sepolia.voyager.online/contract/0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262)。

如果要从命令行重新读取链上状态：

```bash
ROUND=0x05b255273527a9f79cac4543a2a2d1bd2bf0128db60910a9d1764306d8e76262

sncast --profile amaci_local_oz call --contract-address "$ROUND" --function get_state_commitment
sncast --profile amaci_local_oz call --contract-address "$ROUND" --function get_deactivate_commitment
sncast --profile amaci_local_oz call --contract-address "$ROUND" --function get_tally_commitment
sncast --profile amaci_local_oz call --contract-address "$ROUND" --function get_keys_added
sncast --profile amaci_local_oz call --contract-address "$ROUND" --function get_message_batches_processed
sncast --profile amaci_local_oz call --contract-address "$ROUND" --function get_total_facts_accepted
sncast --profile amaci_local_oz call --contract-address "$ROUND" --function get_tally_submitted
```

后续复核时，优先看这些本地记录：

| purpose | file or directory |
| --- | --- |
| 原始业务输入和链路 commitment | `target/full-component-e2e-20260518T023503Z/inputs/` |
| 所有 Atlantic query id / circuit 映射 | `target/full-component-e2e-20260518T023503Z/atlantic-submissions.json` |
| Atlantic credit 报价汇总 | `target/full-component-e2e-20260518T023503Z/atlantic-credit-cost-summary.json` |
| Atlantic proof verification 链上 gas 汇总 | `target/full-component-e2e-20260518T023503Z/atlantic-proof-verification-fees.json` |
| Atlantic 每个 query 的最终 summary | `target/full-component-e2e-20260518T023503Z/*/atlantic-status/final-query-summary.json` |
| Atlantic proof verification tx receipt | `target/full-component-e2e-20260518T023503Z/atlantic-verification-receipts/` |
| wrapper 调用结果和 tx hash | `target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-execution-results.json` |
| wrapper 成本和最终链上状态 | `target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-cost-summary.json` |
| wrapper 每笔交易 receipt | `target/full-component-e2e-20260518T023503Z/chain-full-wrapper/receipts/` |

deploy tx：

```text
0x0757cc62acbf464d8c94b4b1a3d78d8174ed4e1bca61f446726d889a51533a5a
```

deploy actual fee：

```text
59921199059160160 fri (~0.0599211991 STRK)
```

完整 wrapper 执行顺序：

```text
allow process component program hashes x5
submit add-new-key-native fact
submit process-message-coord-key-native fact
submit process-message-ecdh-native fact x5
submit process-message-decrypt-native fact x5
submit process-message-signature-native fact x5
submit process-message-step-core-native fact x5
submit process-messages-boundary-native fact
submit tally-native fact
```

执行结果：

| scope | count | actual fee |
| --- | ---: | ---: |
| allow component program hashes | `5` | `60144796318744256 fri` (~`0.0601447963 STRK`) |
| submit facts total | `24` | `590886420648806304 fri` (~`0.5908864206 STRK`) |
| wrapper stages total | `29` | `651031216967550560 fri` (~`0.6510312170 STRK`) |
| deploy + wrapper stages | `30` | `710952416026710720 fri` (~`0.7109524160 STRK`) |

按 round 业务阶段拆分，不含 allowlist 和 deploy：

| flow | component submits | actual fee |
| --- | ---: | ---: |
| add new key | `1` | `38105750570065984 fri` (~`0.0381057506 STRK`) |
| processMessage full component flow | `22` | `521297054607978400 fri` (~`0.5212970546 STRK`) |
| tally | `1` | `31483615470761920 fri` (~`0.0314836155 STRK`) |
| total business submits | `24` | `590886420648806304 fri` (~`0.5908864206 STRK`) |

`processMessage` 内部成本：

| component | count | actual fee |
| --- | ---: | ---: |
| coord-key | `1` | `16884401627299328 fri` (~`0.0168844016 STRK`) |
| ecdh | `5` | `87660310083271936 fri` (~`0.0876603101 STRK`) |
| decrypt | `5` | `89669898808469504 fri` (~`0.0896698988 STRK`) |
| signature | `5` | `94917889876427008 fri` (~`0.0949178899 STRK`) |
| step-core | `5` | `204306678686164736 fri` (~`0.2043066787 STRK`) |
| boundary | `1` | `27857875526345888 fri` (~`0.0278578755 STRK`) |

逐笔 wrapper tx、receipt、dry-run 估算和 fee 已落盘：

```text
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-execution-results.json
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/wrapper-cost-summary.json
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/receipts
target/full-component-e2e-20260518T023503Z/chain-full-wrapper/logs
```

关键业务交易：

| stage | query id | tx | actual fee |
| --- | --- | --- | ---: |
| `add-new-key-native` | `01KRWF659REJ90DGBF16MTRWAG` | `0x07add36b0c8df227b5740ef238e2a6761709919c435810f562a0162905f99170` | `38105750570065984 fri` |
| `process-messages-boundary-native` | `01KRWH2N5YDNB31AH3CHBEMMJP` | `0x01253237213d436d1f9d0312896e79cccb6c03605652e38e89309ad796095b9f` | `27857875526345888 fri` |
| `tally-native` | `01KRWH2PHX0E6A02GJE82EB94A` | `0x0097d44d00d4124454df39b5108924e8bbb873236879fe5df1bc3d16726a8049` | `31483615470761920 fri` |

最终链上状态：

```text
get_state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

get_deactivate_commitment =
0x2838ad41c0aecc7fce6b9df78cdd4cbb485f329fd63dd7c44adea2f8583de94

get_tally_commitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc

get_keys_added = 0x1
get_message_batches_processed = 0x1
get_deactivate_batches_processed = 0x0
get_total_facts_accepted = 0x18
get_tally_submitted = true
```

本轮结论：完整小电路拆分口径下，`add new key -> processMessage full component flow -> tally` 已经在 Starknet Sepolia 通过 Atlantic registered facts 和 `MockAmaciRound` wrapper 串通。当前成本统计里的 `0.5908864206 STRK` 是 24 个 proof facts 被 wrapper 消费的业务交易成本；`0.6510312170 STRK` 额外包含 5 个 component program hash allowlist 交易；`0.7109524160 STRK` 再额外包含本轮部署 round wrapper 的交易。

## Milestone 2 Segment Wrapper Run 2026-05-22

这轮验证的是 processMessage proof 粒度优化后的路径。原完整 component round 的 processMessage 部分需要 22 个 fact：

```text
coord-key x1
ecdh x5
decrypt x5
signature x5
step-core x5
boundary x1
```

本轮改为两个 stage segment fact：

```text
tail3: messages[2..4]
head2: messages[0..1]
```

因此完整业务路径从：

```text
add-key x1 + processMessage x22 + tally x1 = 24 facts
```

降为：

```text
add-key x1 + processMessage segment x2 + tally x1 = 4 facts
```

### Atlantic Segment Queries

fixed segment artifacts：

```text
target/segment-stage-e2e-fixed-20260522T070423Z
```

| stage | Atlantic query id | status | program hash | integrity fact hash |
| --- | --- | --- | --- | --- |
| tail3 | `01KS789XFZB1W480HCFHHPBYHW` | DONE / PROOF_VERIFICATION_ON_L2 | `0x629bd3434387bfd139c424ac566f46cfe9cb7efd7dabef9874c3a6cb96a33fc` | `0x735298b2398cb6926bfc56f631c8bf56997cdea3fe6a58b3238e4de023bd2df` |
| head2 | `01KS78A9FWD39S2YZWQ8MY0YRA` | DONE / PROOF_VERIFICATION_ON_L2 | `0x629bd3434387bfd139c424ac566f46cfe9cb7efd7dabef9874c3a6cb96a33fc` | `0x4bab46c4095ad95750f426a843e7688cf1ba6c9e2a2d7ee6049a9a218f1fa78` |

注意：第一次 full e2e segment 提交过一组 pre-fix query，但 head2 的中间 state commitment salt 链接不正确，不应用于 round wrapper。fixed 后本地链接关系为：

```text
tail3.current = 0x1e717935e50b681995682b2d0c5e3706756ac59395d910debf166fc9f3f25e5
tail3.new     = 0x6f0e80965209462001201fc9a0acfac6798fe2be6537aa8dcf169875593a172
head2.current = 0x6f0e80965209462001201fc9a0acfac6798fe2be6537aa8dcf169875593a172
head2.new     = 0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775
```

### Segment Wrapper Execution

新部署的 `MockAmaciRound` 使用 segment program hash 作为 `process_messages_program_hash`：

```text
0x629bd3434387bfd139c424ac566f46cfe9cb7efd7dabef9874c3a6cb96a33fc
```

链上地址：

| item | value |
| --- | --- |
| MockAmaciRound segment wrapper | [0x05774fb80c7e6bc13221960d5e29d6068594f11b4401bd18449dd21892e51cb5](https://sepolia.voyager.online/contract/0x05774fb80c7e6bc13221960d5e29d6068594f11b4401bd18449dd21892e51cb5) |
| deploy tx | [0x0279dcef8f3a6fae6f1a0afe7cdd70bd3e368b9a3fe01507ade187b1cb600186](https://sepolia.voyager.online/tx/0x0279dcef8f3a6fae6f1a0afe7cdd70bd3e368b9a3fe01507ade187b1cb600186) |
| add-key submit tx | [0x01864370f58c1904f9ee0d2cf61fb47bc0d0dee318fa9565a56d4395fc70f7c4](https://sepolia.voyager.online/tx/0x01864370f58c1904f9ee0d2cf61fb47bc0d0dee318fa9565a56d4395fc70f7c4) |
| tail3 submit tx | [0x027090554a0ae0166f502445687d20c712b806a1d4275a905bc6dcb6243faf05](https://sepolia.voyager.online/tx/0x027090554a0ae0166f502445687d20c712b806a1d4275a905bc6dcb6243faf05) |
| head2 submit tx | [0x06f538c1a83deb17c750bba755ecb428b04909938065c1139318248bfb520e2c](https://sepolia.voyager.online/tx/0x06f538c1a83deb17c750bba755ecb428b04909938065c1139318248bfb520e2c) |
| tally submit tx | [0x063352207ccb1e09f96dacff26773961f638eb509d222e195c410032ec481147](https://sepolia.voyager.online/tx/0x063352207ccb1e09f96dacff26773961f638eb509d222e195c410032ec481147) |

本地记录：

```text
target/segment-stage-e2e-fixed-20260522T070423Z/chain-segment-wrapper
target/segment-stage-e2e-fixed-20260522T070423Z/chain-segment-wrapper/wrapper-cost-summary.json
target/segment-stage-e2e-fixed-20260522T070423Z/chain-segment-wrapper/receipts
```

业务提交费用：

| stage | actual fee | l1 data gas | l2 gas |
| --- | ---: | ---: | ---: |
| add-new-key-native | `0.039046820390887166 STRK` | 576 | 4,762,880 |
| process-messages-tail3-native | `0.09080193917119629 STRK` | 416 | 11,265,040 |
| process-messages-head2-native | `0.08753597131207001 STRK` | 384 | 10,863,040 |
| tally-native | `0.032221231057083966 STRK` | 448 | 3,935,200 |
| business total | `0.24960596193123744 STRK` | | |

部署费用：

```text
deploy: 0.06212580869448576 STRK
business + deploy total: 0.3117317706257232 STRK
```

最终链上状态：

```text
get_state_commitment =
0x6870bab41e9daf5aae373119bec58a46700a063002f69586bc0158770b0c775

get_deactivate_commitment =
0x2838ad41c0aecc7fce6b9df78cdd4cbb485f329fd63dd7c44adea2f8583de94

get_tally_commitment =
0x43ade83b1ca050d3f5d89c0e8c8b93b598387322c82d9f894ac321cd48348cc

get_keys_added = 0x1
get_message_batches_processed = 0x2
get_deactivate_batches_processed = 0x0
get_total_facts_accepted = 0x4
get_tally_submitted = true
```

对比完整 component wrapper run：

| item | full component | segment wrapper |
| --- | ---: | ---: |
| processMessage facts | 22 | 2 |
| total business facts | 24 | 4 |
| business wrapper fee | `0.5908864206 STRK` | `0.2496059619 STRK` |
| processMessage wrapper fee | `0.5212970546 STRK` | `0.1783379105 STRK` |

这轮说明：在不改变 add-key/tally 数据的前提下，`tail3 + head2` segment proof 可以替代原来的 22 个 processMessage component facts，并在 Starknet Sepolia 上完成同一个 round 状态推进和最终 tally commitment 校验。

### Atlantic Proof Verification Fees

Atlantic 侧真实 proof verification 成本可以通过官方 query jobs API 批量查询：

```text
GET https://atlantic.api.herodotus.cloud/atlantic-query-jobs/<query-id>
```

其中 `PROOF_VERIFICATION.context` 会给出 Atlantic 代提交到 Sepolia 的多笔 transaction hash，例如：

```text
initial.transactionHash
step1.transactionHash
...
final.transactionHash
```

再用 Starknet RPC 的 `starknet_getTransactionReceipt` 拉这些 tx receipt，就可以得到每笔 `actual_fee`。本轮已批量完成查询。

本地记录：

```text
target/full-component-e2e-20260518T023503Z/atlantic-proof-verification-fees.json
target/full-component-e2e-20260518T023503Z/atlantic-proof-verification-fees.md
target/full-component-e2e-20260518T023503Z/atlantic-query-jobs
target/full-component-e2e-20260518T023503Z/atlantic-verification-receipts
```

Atlantic proof verification 链上费用：

| scope | queries | verification txs | actual fee |
| --- | ---: | ---: | ---: |
| add new key | `1` | `9` | `3.856539616 STRK` |
| processMessage full component flow | `22` | `197` | `87.441747888 STRK` |
| tally | `1` | `9` | `3.819034506 STRK` |
| total | `24` | `215` | `95.117322010 STRK` |

按单个 query 展开：

| circuit | query id | verification txs | actual fee |
| --- | --- | ---: | ---: |
| `add-new-key-native` | `01KRWF659REJ90DGBF16MTRWAG` | `9` | `3.856539616 STRK` |
| `process-message-coord-key-native` | `01KRWF6757RZ1MWBQY732ZSXTQ` | `9` | `3.822048762 STRK` |
| `process-message-decrypt-native-0` | `01KRWF68YFZVQQV91AAF8A58W8` | `9` | `3.870004597 STRK` |
| `process-message-decrypt-native-1` | `01KRWF6AQCDR6X3A75WZ42N3RJ` | `9` | `3.831791478 STRK` |
| `process-message-decrypt-native-2` | `01KRWF6CG8BPASBRQ0R2PM3HQF` | `9` | `3.874023852 STRK` |
| `process-message-decrypt-native-3` | `01KRWF6ER32A3C4XM2MDA729D2` | `9` | `3.888603026 STRK` |
| `process-message-decrypt-native-4` | `01KRWF6GH1W4AGPYQSTV6RWRTV` | `9` | `3.832167795 STRK` |
| `process-message-ecdh-native-0` | `01KRWF6K57JDS4PJZXMPK9G1GK` | `9` | `3.886272949 STRK` |
| `process-message-ecdh-native-1` | `01KRWF6MXBC7V6BQ3VJ4DHV6CX` | `9` | `3.857766967 STRK` |
| `process-message-ecdh-native-2` | `01KRWF6PSQEHXRECS1D7ZPADMR` | `9` | `3.895975028 STRK` |
| `process-message-ecdh-native-3` | `01KRWF6SDAR8QM600W1FW0YQSF` | `9` | `3.900966671 STRK` |
| `process-message-ecdh-native-4` | `01KRWF6V542EB3ASN26Q45YWRV` | `9` | `3.886608758 STRK` |
| `process-message-signature-native-0` | `01KRWF6X2H9QVJDBNEN99WANSG` | `9` | `3.893991754 STRK` |
| `process-message-signature-native-1` | `01KRWF6YTM5EKJGBTVX6PTB0KP` | `9` | `3.881972603 STRK` |
| `process-message-signature-native-2` | `01KRWH1Z0VE3X9HBA7Y97KEZYH` | `9` | `3.851180870 STRK` |
| `process-message-signature-native-3` | `01KRWH20JK309DY0K6W45TZNY9` | `9` | `3.886457367 STRK` |
| `process-message-signature-native-4` | `01KRWH230DNQTQTFD7RVS3SF1A` | `9` | `3.873708872 STRK` |
| `process-message-step-core-native-0` | `01KRWH24FQ8GMCYRQFQXKSZS4H` | `9` | `4.379992697 STRK` |
| `process-message-step-core-native-1` | `01KRWH27MGCT0Y8C6A3DZY332R` | `9` | `4.362533493 STRK` |
| `process-message-step-core-native-2` | `01KRWH2AW97HJJSVYVK59DYG72` | `9` | `4.448536694 STRK` |
| `process-message-step-core-native-3` | `01KRWH2E3P570YYQ6PA302Z4RE` | `9` | `4.457445495 STRK` |
| `process-message-step-core-native-4` | `01KRWH2J73BS432F0TWQTAXSBN` | `9` | `4.394341491 STRK` |
| `process-messages-boundary-native` | `01KRWH2N5YDNB31AH3CHBEMMJP` | `8` | `3.465356672 STRK` |
| `tally-native` | `01KRWH2PHX0E6A02GJE82EB94A` | `9` | `3.819034506 STRK` |

两层成本合并口径：

| scope | actual fee |
| --- | ---: |
| Atlantic proof verification only | `95.117322010 STRK` |
| AMACI business fact consumption only | `0.590886421 STRK` |
| proof verification + business consumption | `95.708208431 STRK` |
| plus component allowlist | `95.768353227 STRK` |
| plus round wrapper deploy | `95.828274426 STRK` |

这个合并口径说明：目前完整拆分版 round 的主要成本在 Atlantic/Integrity proof verification 交易，不在我们自己的 wrapper fact consumption 交易。

### Atlantic Credit Cost

如果把 proof 生成、proof verification、以及 verification 交易提交全部外包给 Atlantic，成本应按 Atlantic credits 统计，而不是按我们账户的 STRK 支出统计。

本轮本地状态文件没有直接暴露 accepted query 的最终扣费字段，但我们有两个可用口径：

1. **实际 API/x402 quote 口径**：本轮 credit 不足时，Atlantic 对 `S` query 返回的 `paymentRequired.extra.creditAmount = 300`，即每个 `S` query 需要 `300 credits`。
2. **官方 pricing 文档口径**：trace generation 为每个 started minute `1 credit`；`S` proof generation 为 `70 credits`；testnet proof verification 免费，mainnet proof verification 为每 proof `25 credits`。

本轮 24 个 query 全部是 `jobSize = S`。所有 trace job 都小于 1 分钟，因此按 started minute 计算是每 query `1 trace credit`。

本地记录：

```text
target/full-component-e2e-20260518T023503Z/atlantic-credit-cost-summary.json
target/full-component-e2e-20260518T023503Z/atlantic-credit-cost-summary.md
```

按实际 API/x402 quote 口径，也就是更保守、更接近账务支付请求的口径：

| flow | queries | credits | USD at $0.01/credit |
| --- | ---: | ---: | ---: |
| add new key | `1` | `300` | `$3.00` |
| processMessage full component flow | `22` | `6600` | `$66.00` |
| tally | `1` | `300` | `$3.00` |
| total | `24` | `7200` | `$72.00` |

按官方 pricing 文档公式估算：

| flow | queries | trace minutes | testnet credits | testnet USD | mainnet credits | mainnet USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| add new key | `1` | `1` | `71` | `$0.71` | `96` | `$0.96` |
| processMessage full component flow | `22` | `22` | `1562` | `$15.62` | `2112` | `$21.12` |
| tally | `1` | `1` | `71` | `$0.71` | `96` | `$0.96` |
| total | `24` | `24` | `1704` | `$17.04` | `2304` | `$23.04` |

当前建议：做预算和向外沟通时先使用 `7200 credits / $72` 这个实际 API quote 口径，因为这是 Atlantic 在 insufficient credits/x402 flow 中实际要求补足的 `S` query 支付量。官方 pricing 文档口径可以作为理论解释和后续跟 Herodotus 对账时的问题点：为什么公开 pricing 的 `S=70 credits + trace` 与实际 x402 quote 的 `S=300 credits` 存在差异。
