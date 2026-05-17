# AMACI E2E Round Notes

本文档记录 AMACI native/Atlantic/Starknet E2E round 的实际验证进度。当前已经真实打通的是 `tally` 路径；`add_new_key`、`process_messages`、`process_deactivate` 的合约消费入口和本地导出工具已经补齐，等待各自 Atlantic query 完成后即可按同一模式提交链上 fact。

## Tally

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

## Remaining Native Circuits

### 当前状态

除 `tally` 外，`MockAmaciRound` 已补齐以下 Atlantic metadata fact 消费入口：

```text
submit_add_new_key_atlantic_metadata_fact
submit_process_messages_atlantic_metadata_fact
submit_process_deactivate_atlantic_metadata_fact
submit_operation_atlantic_metadata_fact
```

`export:atlantic-round-call` 也已经支持按 operation 生成提交命令：

```text
--operation add-new-key
--operation process-messages
--operation process-deactivate
--operation generic
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
contracts tests: 27 passed
npm test: 157 tests, 146 passed, 11 skipped, 0 failed
```

### 当前限制

这次验证证明 tally proof 可以通过 Atlantic 路径上链并被 AMACI mock wrapper 消费。但当前仍是 E2E 成本评估和流程验证用的 mock round，不是生产 AMACI 合约。

生产化前还需要补齐：

1. `add_new_key`、`process_messages`、`process_deactivate` 的 Atlantic query 实际提交、完成后链上 fact 消费。
2. metadata program hash 的生产级 allowlist/信任策略。
3. 完整 round 中各阶段状态承接、权限、重复提交和 replay 防护。
4. 交易 gas/fee 的系统化记录。
