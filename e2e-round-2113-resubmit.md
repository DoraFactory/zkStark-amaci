# AMACI Starknet-native E2E Round 记录：2-1-1-3 生命周期

本文档记录 2026-05-25 使用最新 Starknet-native Cairo 电路完成的一轮 AMACI E2E 测试。测试目标是验证当前 2-1-1-3 参数下，`signup -> vote -> deactivate -> vote -> processMsg -> tally` 业务流程可以通过本地 Cairo 执行、Atlantic proof generation + L2 proof verification，并由 Starknet Sepolia 上的 `MockAmaciRound` 合约消费已注册 fact，完成链上状态推进。

本轮使用的是新的 Starknet-native 协议路径：STARK curve、STARK ECDSA、STARK curve ECDH / decrypt point relation、Starknet Poseidon domain-separated hash/KDF。旧 BabyJubJub / BN254 / Circom compatibility 路径不参与本轮测试。

## 结论

本轮闭环已完成：

```text
JS lifecycle fixture
  -> Cairo Starknet-native input
  -> local Cairo execution
  -> Atlantic program/input bundle
  -> Atlantic proof generation + L2 proof verification
  -> MockAmaciRound consume registered metadata facts on Starknet Sepolia
  -> on-chain final state check
```

最终结果：

| item | result |
| --- | --- |
| Local Cairo execution | `4/4 stages ok` |
| Atlantic queries | `4/4 DONE` |
| Atlantic result | `4/4 PROOF_VERIFICATION_ON_L2` |
| Starknet wrapper submits | `4/4 SUCCEEDED` |
| Final on-chain state check | all matched |
| `npm test` | `76 passed, 7 skipped` |
| Cairo execution tests | `7 passed` |
| Contract tests | `38 passed, 0 failed` |
| Business wrapper fee, excluding deploy | `0.254386565039634 STRK` |
| Wrapper fee, including deploy | `0.32220308385814067 STRK` |
| Atlantic proof verification gas | `18.844152022218264 STRK` |
| Atlantic credit estimate | `4 * S query` |

## 本轮产物

本轮所有本地文件都在：

```text
/Users/bun/DoraFactory/maci/zkStark-amaci/target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633
```

关键文件：

| file | purpose |
| --- | --- |
| `fixture/chain.json` | 本轮业务 fixture 的完整状态、消息、commitment 和 tally 结果 |
| `flow-manifest.json` | E2E 数据流、stage 文件路径、命令模板 |
| `generated-query-map.json` | stage 到 Atlantic query id 的映射 |
| `stages/*/atlantic-query/` | 提交给 Atlantic 的 Cairo1 programFile/inputFile/bundle |
| `stages/*/atlantic-result/` | Atlantic status、metadata、proof、query summary |
| `chain-wrapper/*-wrapper-call.json` | 真实 Starknet wrapper calldata 和 invoke command |
| `wrapper-flow-check.json` | 本地 wrapper 状态机模型校验 |
| `final-fetch-with-artifacts.txt` | Atlantic artifact fetch 结果 |

## 测试参数和业务数据

本轮协议参数：

| param | value |
| --- | ---: |
| stateTreeDepth | `2` |
| intStateTreeDepth | `1` |
| voteOptionTreeDepth | `1` |
| messageBatchSize | `3` |
| signupCount | `1` |

业务流程：

```text
signup
vote
deactivate
vote
processMsg
tally
```

本轮只有 1 个 signup 用户，active state index 是 `1`。消息批次大小为 `3`，因此本轮 `processMsg` 一次处理 3 条 vote command。

三条 vote command：

| command order in fixture | state index | vote option | new vote weight | valid |
| ---: | ---: | ---: | ---: | --- |
| 0 | `1` | `2` | `5` | true |
| 1 | `1` | `1` | `3` | true |
| 2 | `1` | `0` | `2` | true |

fixture 里 process message 的处理顺序是从 message index `2` 处理到 `0`。为了覆盖生命周期，本轮把最早的 1 条 vote 放在 deactivate 前，后两条 vote 放在 deactivate 后：

| lifecycle placement | message indexes |
| --- | --- |
| before deactivate | `[2]` |
| after deactivate | `[1, 0]` |

最终 vote leaves for state index `1`：

```text
[2, 3, 5, 0, 0]
```

tally 输出的新结果：

```text
[
  2000000000000000000000004,
  3000000000000000000000009,
  5000000000000000000000025,
  0,
  0
]
```

## Commitment 链接

本轮关键 commitment：

| value | decimal |
| --- | --- |
| signup initial state commitment | `3559439916355578108112892362874064789591969532224976912093089453945162584775` |
| deactivate current commitment | `2587079882933254069663414914739030721717169098678022046322103954536561925700` |
| deactivate new commitment | `1917604265108373395770517861582458055299312716124589564463891041097888928625` |
| processMessages new state commitment | `3338270790180365427390780126912701898651581654534666111635510161461235111027` |
| tally new commitment | `279312577360343137726496067462649075989164846589493453337614393131008780620` |

Hex 形式：

| value | hex |
| --- | --- |
| signup initial state commitment | `0x7de92544eb74ab0902ea300f7d8678631dc66cb4d587f17c7f9cf685a8052c7` |
| deactivate current commitment | `0x5b83c3e2415c567438d37c35579a0505b5d78f36d78b0683f697af0fb185e44` |
| deactivate new commitment | `0x43d535758e4fd78a7007a791076ef3b0fbaa02e46024c903edde4c95b4d9371` |
| processMessages new state commitment | `0x76164f179d947fc1701b6886da257822f95fdabfe1217c19e8847a3696f5473` |
| tally new commitment | `0x9e15d74c9162bd2d53f3bbfa228ca9ac012f85328592219230a186c6fbe94c` |

链接关系：

| link | status |
| --- | --- |
| `processDeactivate.newDeactivateCommitment -> processMessages.deactivateCommitment` | true |
| `processMessages.newStateCommitment -> tally.stateCommitment` | true |

## Atlantic 提交

本轮提交给 Atlantic 的不是本地 Stone proof JSON，而是每个 stage 的 Cairo1 program file、Cairo1 Rust VM input file 以及 proving/verification 参数。Atlantic 负责 trace/proof/proof verification，并把 fact 注册到 Starknet 上。

| stage | circuit | query id | Atlantic transaction id | status | result |
| --- | --- | --- | --- | --- | --- |
| addNewKey | `add-new-key-native` | `01KSFS206SC3MN3QMD12R08CPM` | `01KSFS26W33SV5TKX9SXSJM2KH` | DONE | `PROOF_VERIFICATION_ON_L2` |
| processDeactivate | `process-deactivate-stage-native` | `01KSFS27AJDWWWGQWRKGH6N8XT` | `01KSFS2NE98JTE1H0HXM0B5J90` | DONE | `PROOF_VERIFICATION_ON_L2` |
| processMessages | `process-messages-stage-native` | `01KSFS2FSSYBNDT57ZD39Y8XWK` | `01KSFS2Y4D0691HWVCKKVA2H8H` | DONE | `PROOF_VERIFICATION_ON_L2` |
| tally | `tally-native` | `01KSFS2PTWSP9GGQEDB5Q09H3G` | `01KSFS2X1WPM8AV0NH9PHGDQJK` | DONE | `PROOF_VERIFICATION_ON_L2` |

Atlantic Console 链接：

| stage | url |
| --- | --- |
| addNewKey | `https://www.herodotus.cloud/en/atlantic/01KSFS206SC3MN3QMD12R08CPM` |
| processDeactivate | `https://www.herodotus.cloud/en/atlantic/01KSFS27AJDWWWGQWRKGH6N8XT` |
| processMessages | `https://www.herodotus.cloud/en/atlantic/01KSFS2FSSYBNDT57ZD39Y8XWK` |
| tally | `https://www.herodotus.cloud/en/atlantic/01KSFS2PTWSP9GGQEDB5Q09H3G` |

Program hash 和 fact hash：

| stage | program hash | integrity fact hash | sharp fact hash |
| --- | --- | --- | --- |
| addNewKey | `0x61ad9bfc1fc9d3a6ddfce81aab892589dda97e8e432e2ac6df9f008bc71b4cd` | `0x7dd37761b3081984c186c958d29bdc2ecfbd2a9e419398795929b20b5bea496` | `0x10dfd83df0aa7702b0badc1eefba20642e8e6c2ff6ebd0da3044f45715d404f8` |
| processDeactivate | `0x42588094df18531d7ce927b10403a0975e272dd30091399d9ffa605f7777119` | `0x48ee1aaf5339b1aa658a9c0a088100362f62ea0083ba17e1deb33686aa79c6a` | `0x354f37b2786229e9687266e72f1ebf01109474edfbc2684dad0e89e1c98fcdd4` |
| processMessages | `0x6d6540adacef60af427027b133a8a5b0d4a40661ec8d3c6ed19460319a4c458` | `0x209d74fefc95c2184a295aa1287b785586ae8f261d95839d8b6a8a07c83b205` | `0xd91dedc05c3dc847d93987dffd094060ff7809a5a9d6f26dc55e5b7c703870e6` |
| tally | `0x46f4e3ce5ef38dc13944476010804d52c8c24afca094c24b6b0a608d8591425` | `0x4813e50fe2e6525ba8ac542aade6669fac40a6bbc0db891b430cf117ccab5dd` | `0x652bf39d3a3327e39987f14a331ea36ef494df2311913fd612bdf29e1e377666` |

## Atlantic proof verification 费用

Atlantic 每个 stage 的 `PROOF_VERIFICATION` job 会在 Starknet 上提交多笔 verification tx。本轮通过 Atlantic query jobs API 拉取 verification tx hash，再用 Starknet Sepolia RPC 读取 receipt 汇总费用。

| stage | verification txs | actual fee | l1 data gas | l2 gas |
| --- | ---: | ---: | ---: | ---: |
| addNewKey | `8` | `4.363784302958668 STRK` | `3936` | `545246800` |
| processDeactivate | `8` | `5.095447549085652 STRK` | `3936` | `636704720` |
| processMessages | `9` | `5.4876636731420065 STRK` | `5120` | `685662560` |
| tally | `9` | `3.8972564970319388 STRK` | `4192` | `486915920` |
| total | `34` | `18.844152022218264 STRK` | | |

这些费用是 Atlantic 代我们做 proof verification 和 fact 注册时在 Starknet 上产生的 gas。它不是我们业务账户直接支付的 wrapper 调用费。

## Starknet 合约部署和业务侧提交

部署信息：

| item | value |
| --- | --- |
| network | Starknet Sepolia |
| profile | `amaci_local_oz` |
| contract | `MockAmaciRound` |
| class hash | `0x07fee61ef52e9d2c1fdce0f72629d824c654e3851193f89144092057b4387dad` |
| contract address | `0x0158434ad2308bf2ab25aa05044b326278a137aec2bef092176d56e493a5df1c` |
| FactRegistry mode | satellite |
| FactRegistry address | `0x00421cd95f9ddabdd090db74c9429f257cb6bc1ccc339278d1db1de39156676e` |
| admin/account | `0x0424d1afc810222071c9eac2cd1b926c0b75d8c92f88d392d53e725f4f08e760` |
| deploy tx | `0x05bfa958164907b5c7c2c7e67546c936a98fd214cebeaa5b0b71b8a638d5b122` |

Voyager：

```text
https://sepolia.voyager.online/contract/0x0158434ad2308bf2ab25aa05044b326278a137aec2bef092176d56e493a5df1c
https://sepolia.voyager.online/tx/0x05bfa958164907b5c7c2c7e67546c936a98fd214cebeaa5b0b71b8a638d5b122
```

constructor 关键参数：

| param | value |
| --- | --- |
| `min_security_bits` | `50` |
| `add_new_key_program_hash` | `0x61ad9bfc1fc9d3a6ddfce81aab892589dda97e8e432e2ac6df9f008bc71b4cd` |
| `process_messages_program_hash` | `0x6d6540adacef60af427027b133a8a5b0d4a40661ec8d3c6ed19460319a4c458` |
| `process_deactivate_program_hash` | `0x42588094df18531d7ce927b10403a0975e272dd30091399d9ffa605f7777119` |
| `tally_program_hash` | `0x46f4e3ce5ef38dc13944476010804d52c8c24afca094c24b6b0a608d8591425` |
| `initial_state_commitment` | `0x7de92544eb74ab0902ea300f7d8678631dc66cb4d587f17c7f9cf685a8052c7` |
| `initial_deactivate_commitment` | `0x5b83c3e2415c567438d37c35579a0505b5d78f36d78b0683f697af0fb185e44` |
| `initial_tally_commitment` | `0x0` |

业务侧 wrapper submit：

| stage | function | tx | actual fee | l1 data gas | l2 gas | result |
| --- | --- | --- | ---: | ---: | ---: | --- |
| addNewKey | `submit_add_new_key_atlantic_metadata_fact` | `0x06e4e120a50ab8617af6dc7a42eda869a70dce1544ec6e012f518837b8eb8644` | `0.03522312610538208 STRK` | `480` | `4371120` | SUCCEEDED |
| processDeactivate | `submit_process_deactivate_atlantic_metadata_fact` | `0x05e990022bbeea38c29e2c7c278cc87dd70ccd0536a5acf5470cdcc073da8053` | `0.09714516907370359 STRK` | `416` | `12115600` | SUCCEEDED |
| processMessages | `submit_process_messages_atlantic_metadata_fact` | `0x05583c0116fd699c3a28602233aa81ad84cfd1e15a53cf8312fa0ec592260e0b` | `0.09029962511157955 STRK` | `416` | `11259920` | SUCCEEDED |
| tally | `submit_tally_atlantic_metadata_fact` | `0x058daed5162bbe1babe5fd180af83eb5c27ff6bc851cb321f6ed3fbd836d75c1` | `0.03171864474896883 STRK` | `448` | `3935200` | SUCCEEDED |

业务侧费用：

| scope | actual fee |
| --- | ---: |
| deploy | `0.06781651881850659 STRK` |
| business wrapper submits, excluding deploy | `0.254386565039634 STRK` |
| wrapper total, including deploy | `0.32220308385814067 STRK` |

## 最终链上状态校验

最终读取 `MockAmaciRound` 状态，并和本地 fixture 预期值比较：

| field | expected | actual | matched |
| --- | --- | --- | --- |
| stateCommitment | `0x76164f179d947fc1701b6886da257822f95fdabfe1217c19e8847a3696f5473` | `0x76164f179d947fc1701b6886da257822f95fdabfe1217c19e8847a3696f5473` | true |
| deactivateCommitment | `0x43d535758e4fd78a7007a791076ef3b0fbaa02e46024c903edde4c95b4d9371` | `0x43d535758e4fd78a7007a791076ef3b0fbaa02e46024c903edde4c95b4d9371` | true |
| tallyCommitment | `0x9e15d74c9162bd2d53f3bbfa228ca9ac012f85328592219230a186c6fbe94c` | `0x9e15d74c9162bd2d53f3bbfa228ca9ac012f85328592219230a186c6fbe94c` | true |
| keysAdded | `0x1` | `0x1` | true |
| messageBatchesProcessed | `0x1` | `0x1` | true |
| deactivateBatchesProcessed | `0x1` | `0x1` | true |
| totalFactsAccepted | `0x4` | `0x4` | true |
| tallySubmitted | `true` | `true` | true |

## 命令记录

本地完整 round 执行和 wrapper 模型校验：

```bash
node tools/run-e2e-round-flow.mjs \
  --out-dir target/e2e-round-flow-stark-native-postfix-local2 \
  --execute-local \
  --simulate-wrapper \
  --text
```

生成 fixture、本地校验、提交 Atlantic 的入口命令：

```bash
node tools/run-e2e-round-flow.mjs \
  --out-dir target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633 \
  --execute-local \
  --simulate-wrapper \
  --submit-atlantic \
  --text
```

重新 fetch Atlantic artifact：

```bash
node tools/run-e2e-round-flow.mjs \
  --out-dir target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633 \
  --fixture-dir target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/fixture \
  --query-map target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/generated-query-map.json \
  --fetch-atlantic \
  --text
```

导出 wrapper calldata：

```bash
node tools/export-atlantic-mock-round-call.mjs \
  --query-result target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/stages/<stage>/atlantic-result/atlantic-query-result.json \
  --metadata target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/stages/<stage>/atlantic-result/artifacts/metadata.json \
  --wrapper-address 0x0158434ad2308bf2ab25aa05044b326278a137aec2bef092176d56e493a5df1c \
  --operation <operation> \
  --profile amaci_local_oz \
  --out target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/chain-wrapper/<stage>-wrapper-call.json \
  --text
```

具体 invoke command 已保存在：

```text
target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/chain-wrapper/01-add-new-key-wrapper-call.json
target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/chain-wrapper/02-process-deactivate-wrapper-call.json
target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/chain-wrapper/03-process-messages-wrapper-call.json
target/e2e-round-flow-stark-native-atlantic-postfix2-20260525-223633/chain-wrapper/04-tally-wrapper-call.json
```

测试命令：

```bash
scarb check
npm test
RUN_CAIRO_EXECUTION_TESTS=1 node --test tests/cairo-execution.test.mjs
cd contracts && scarb test
```

## 成本口径说明

本轮存在三类成本，不能混在一起：

1. Atlantic credit：服务账单口径。本轮是 4 个 `S` query。
2. Atlantic proof verification gas：Atlantic 代我们提交 proof verification 和 fact registration 到 Starknet 的链上 gas，本轮 receipt 合计 `18.844152022218264 STRK`。
3. AMACI business wrapper gas：我们自己的业务合约消费 Atlantic 已注册 fact 并推进 round 状态的链上 gas，本轮不含 deploy 是 `0.254386565039634 STRK`，含 deploy 是 `0.32220308385814067 STRK`。

后续做成本汇报时，建议把这三类分开展示：Atlantic 服务成本、Atlantic 代付/代提交的 verification gas、AMACI 合约自身的业务验证和状态更新 gas。
