# AMACI Full Round E2E 中文报告

生成时间：2026-05-28  
测试目录：`zkStark-amaci/target/five-signup-simplified-round`

## 1. 测试结论

这次 E2E 跑的是一个完整的 AMACI round 生命周期：

```text
signup -> deactivate -> processDeactivate -> addNewKey -> vote -> processMessages[0] -> processMessages[1] -> tally[0] -> tally[1]
```

本轮测试覆盖了：

- 5 个原始 signup：`stateIndex = 0,1,2,3,4`
- 2 个真实 deactivate：`stateIndex = 3,4`
- 1 个 addNewKey：旧 `stateIndex = 4` 换到新 `stateIndex = 5`
- 5 条真实投票消息，其中 3 条有效、2 条旧 key 投票应被拒绝
- `processMessages` 分 2 批执行
- `tally` 分 2 批执行
- 6 个 Cairo native stage 全部本地执行通过
- 6 个 Atlantic proving query 全部完成，结果均为 `PROOF_VERIFICATION_ON_L2`

最终统计结果符合预期：

```text
raw results = [1, 0, 0, 0, 10]
```

也就是说：

- `stateIndex 0` 的两条有效投票贡献了 option0=1、option4=5
- old `stateIndex 3` 已 deactivate，后续投票无效
- old `stateIndex 4` 已 deactivate 且换 key，旧 key 后续投票无效
- new `stateIndex 5` 的投票贡献了 option4=5

## 2. 测试场景

### 2.1 signup

初始注册 5 个用户：

| 用户 | stateIndex | 状态 |
| --- | ---: | --- |
| signup 0 | 0 | 初始有效 |
| signup 1 | 1 | 初始有效 |
| signup 2 | 2 | 初始有效 |
| signup 3 | 3 | 后续 deactivate |
| signup 4 | 4 | 后续 deactivate，并 addNewKey |

初始 state commitment：

```text
3304582879249559814324590054632581525881683562562259319454586776991442235000
```

### 2.2 deactivate

真实停用两个旧 key：

| old stateIndex | 预期 |
| ---: | --- |
| 3 | 后续旧 key 投票无效 |
| 4 | 后续旧 key 投票无效，并允许基于停用凭证 addNewKey |

处理后的 deactivate commitment：

```text
36483580362408021606190596304636656148442636981483139730679109185002112544
```

### 2.3 addNewKey

只让 `old stateIndex = 4` 换成新 key：

| 字段 | 值 |
| --- | --- |
| oldStateIndex | 4 |
| newStateIndex | 5 |
| nullifier | `794048109227738880774804643652474150129663166515371306485373579118125268981` |
| deactivateRoot | `3146619146202364040314556657494581387239488382716075020503580931733657947935` |
| newStateCommitment | `869123246040406561332619040119337016619496301659896815633775649807766764056` |

### 2.4 vote

本次测试投的是简化版单选项增量消息。每条 Command 只更新一个 `voteOptionIndex`。

| 序号 | stateIndex | voteOptionIndex | newVoteWeight | 预期效果 |
| ---: | ---: | ---: | ---: | --- |
| 1 | 0 | 0 | 1 | 有效 |
| 2 | 0 | 4 | 5 | 有效 |
| 3 | 3 | 1 | 1 | 无效，old key 已 deactivate |
| 4 | 4 | 2 | 2 | 无效，old key 已 deactivate |
| 5 | 5 | 4 | 5 | 有效，new key 投票 |

预期 raw results：

```text
[1, 0, 0, 0, 10]
```

## 3. 执行过的核心文件

### 3.1 测试与 fixture 生成

| 文件 | 作用 |
| --- | --- |
| `zkStark-amaci/tools/write-five-signup-round-fixture.mjs` | 生成本次 five-signup simplified round 的 fixture |
| `zkStark-amaci/src/fixtures/small-amaci-fixtures.mjs` | 构造 signup/deactivate/addNewKey/processMessages/tally 的测试数据 |
| `zkStark-amaci/tests/five-signup-simplified-round.test.mjs` | E2E 场景断言：顺序、状态转换、两批 message、两批 tally |
| `zkStark-amaci/tests/minimal-round-fixture.test.mjs` | 回归检查 minimal round fixture |

### 3.2 链下输入转换

| 文件 | 作用 |
| --- | --- |
| `zkStark-amaci/src/deactivate/native-cairo-input.mjs` | 生成 processDeactivate native Cairo 输入 |
| `zkStark-amaci/src/add-new-key/cairo-input.mjs` | 生成 addNewKey Cairo 输入 |
| `zkStark-amaci/src/msg/native-cairo-input.mjs` | 生成 processMessages native Cairo 输入 |
| `zkStark-amaci/src/msg/cairo-input.mjs` | message 输入转换与 padding 处理 |
| `zkStark-amaci/src/native-cairo-input.mjs` | native Cairo 输入公共处理 |

### 3.3 Cairo native stage

| stage | Cairo 文件 |
| --- | --- |
| processDeactivate | `zkStark-amaci/cairo/src/native_process_deactivate_stage.cairo` |
| addNewKey | `zkStark-amaci/cairo/src/native_add_new_key.cairo` |
| processMessages | `zkStark-amaci/cairo/src/native_process_messages_stage.cairo` |
| tally | `zkStark-amaci/cairo/src/native_tally_votes.cairo` |

### 3.4 Atlantic/Stone 工具

| 文件 | 作用 |
| --- | --- |
| `zkStark-amaci/tools/run-cairo-execute.mjs` | 本地执行 Cairo native stage |
| `zkStark-amaci/tools/run-stone-air.sh` | 生成 Stone AIR 所需输入 |
| `zkStark-amaci/tools/export-atlantic-query-bundle.mjs` | 导出 Atlantic query bundle |
| `zkStark-amaci/tools/fetch-atlantic-query-result.mjs` | 拉取 Atlantic query 状态与 artifacts |

## 4. 生成的数据文件

### 4.1 fixture 文件

目录：

```text
zkStark-amaci/target/five-signup-simplified-round/fixture
```

生成文件：

| 文件 | 说明 |
| --- | --- |
| `chain.json` | 本轮 round 的流程、状态、投票与 commitment 汇总 |
| `process-deactivate-stage-native.json` | processDeactivate stage 输入 |
| `process-deactivate-boundary-native.json` | processDeactivate boundary 输入 |
| `add-new-key-native.json` | addNewKey 输入 |
| `process-messages-stage-native-0.json` | 第 1 批 processMessages stage 输入 |
| `process-messages-boundary-native-0.json` | 第 1 批 processMessages boundary 输入 |
| `process-messages-stage-native-1.json` | 第 2 批 processMessages stage 输入 |
| `process-messages-boundary-native-1.json` | 第 2 批 processMessages boundary 输入 |
| `tally-native-0.json` | 第 1 批 tally 输入 |
| `tally-native-1.json` | 第 2 批 tally 输入 |

### 4.2 本地 Cairo 执行产物

目录：

```text
zkStark-amaci/target/five-signup-simplified-round/local
```

每个 stage 目录下包含：

- `*-cairo-input.json`
- `*-cairo-args.json`
- `*-prepared.json`
- `execution-run.json`
- `*-stdout.log`
- `*-stderr.log`

本次 6 个本地执行 stage：

```text
processDeactivate
addNewKey
processMessages0
processMessages1
tally0
tally1
```

### 4.3 Atlantic 产物

目录：

```text
zkStark-amaci/target/five-signup-simplified-round/atlantic
```

每个 stage 目录分三类：

| 子目录 | 说明 |
| --- | --- |
| `stone-air` | 本地生成的 Stone AIR 输入、prepared 输入、Sierra program |
| `atlantic-query` | 提交 Atlantic 的 query bundle、program、input、提交脚本 |
| `atlantic-result` | Atlantic 返回状态、summary、proof、metadata、calldata artifacts |

总 query map：

```text
zkStark-amaci/target/five-signup-simplified-round/atlantic/query-map.json
```

本次后续补拉的 proof verification 链上交易与费用数据：

| 文件 | 说明 |
| --- | --- |
| `zkStark-amaci/target/five-signup-simplified-round/proof-verification-costs.json` | 汇总每个 proof verification job 的 tx hash、receipt、actual_fee 和总费用 |
| `zkStark-amaci/target/five-signup-simplified-round/atlantic/<stage>/atlantic-result/jobs.json` | Atlantic jobs endpoint 原始返回；其中 `PROOF_VERIFICATION.context` 包含链上 tx hash |

## 5. 本地验证结果

执行结果汇总：

| 检查项 | 结果 |
| --- | --- |
| `node --test tests/five-signup-simplified-round.test.mjs tests/minimal-round-fixture.test.mjs` | 5 passed |
| `npm test` | 82 passed, 7 skipped, 0 failed |
| 6 个 native stage `scarb execute` | 全部 status 0 |
| `zkStark-amaci/contracts && scarb test` | 41 passed, 0 failed |
| `zkStark-amaci/cairo && scarb test` | 0 tests, ok |

## 6. 状态转换数据

### 6.1 processMessages

| 批次 | currentStateCommitment | newStateCommitment | batchStartHash | batchEndHash |
| ---: | --- | --- | --- | --- |
| 0 | `869123246040406561332619040119337016619496301659896815633775649807766764056` | `1855914912355915712177665349082968848452983248685744177910038027397528745512` | `0` | `2998353314689175414772924753332971623186740056897282904310428893965280397199` |
| 1 | `1855914912355915712177665349082968848452983248685744177910038027397528745512` | `1759591162197939697202246883313813371038817827604853980571769071759289456000` | `2998353314689175414772924753332971623186740056897282904310428893965280397199` | `299464745760970201085427511832308804839965433982842072660465821092804514858` |

### 6.2 tally

| 批次 | currentTallyCommitment | newTallyCommitment | newResults |
| ---: | --- | --- | --- |
| 0 | `0` | `2711702590240115885790755963322345588163573434298960453343474597848051506957` | `[1000000000000000000000001, 0, 0, 0, 5000000000000000000000025]` |
| 1 | `2711702590240115885790755963322345588163573434298960453343474597848051506957` | `530560016888483726568958551519828269471088679267839096851930243754697520525` | `[1000000000000000000000001, 0, 0, 0, 10000000000000000000000050]` |

最终：

```text
raw results = [1, 0, 0, 0, 10]
final encoded results = [1000000000000000000000001, 0, 0, 0, 10000000000000000000000050]
final tally commitment = 530560016888483726568958551519828269471088679267839096851930243754697520525
```

## 7. Atlantic 证明与链接

所有 query 都是：

- `status = DONE`
- `result = PROOF_VERIFICATION_ON_L2`
- `network = TESTNET`
- `chain = L2`
- `isFactMocked = false`
- `isProofMocked = false`

| stage | Atlantic query | externalId | internal transactionId | completedAt |
| --- | --- | --- | --- | --- |
| processDeactivate | [01KSP1TDCQ50J97KDK7WSA6PF7](https://www.herodotus.cloud/en/atlantic/01KSP1TDCQ50J97KDK7WSA6PF7) | `amaci-five-processDeactivate` | `01KSP1TZTGVQ4Q9EXYJ1DRGKF5` | `2026-05-28T01:12:48.604Z` |
| addNewKey | [01KSP1TJMGSQS931S7EHJGRDJM](https://www.herodotus.cloud/en/atlantic/01KSP1TJMGSQS931S7EHJGRDJM) | `amaci-five-addNewKey` | `01KSP1TXVWNEJP2R0TREGN5GWM` | `2026-05-28T01:11:56.001Z` |
| processMessages0 | [01KSP1TNMT5R2Z662AC0NBSF33](https://www.herodotus.cloud/en/atlantic/01KSP1TNMT5R2Z662AC0NBSF33) | `amaci-five-processMessages0` | `01KSP1V2JPSRDGB0BT4M8TACKY` | `2026-05-28T01:13:55.049Z` |
| processMessages1 | [01KSP1TTE7P399CBEXGPHJYWXB](https://www.herodotus.cloud/en/atlantic/01KSP1TTE7P399CBEXGPHJYWXB) | `amaci-five-processMessages1` | `01KSP1V76F3HD2JX5HWEDR7E2P` | `2026-05-28T01:14:14.476Z` |
| tally0 | [01KSP1TY5FHV1N3HKABPB6Y69N](https://www.herodotus.cloud/en/atlantic/01KSP1TY5FHV1N3HKABPB6Y69N) | `amaci-five-tally0` | `01KSP1V47CYWJA1JMB0S5SJRVF` | `2026-05-28T01:14:33.568Z` |
| tally1 | [01KSP1V02HFKQ9W45585YD5E6K](https://www.herodotus.cloud/en/atlantic/01KSP1V02HFKQ9W45585YD5E6K) | `amaci-five-tally1` | `01KSP1VB4B8TA4G26D8H9828PW` | `2026-05-28T01:13:05.335Z` |

注意：这里的 `transactionId` 是 Atlantic 返回的内部 transaction id，不是 Starknet L2 交易哈希。

## 8. Program Hash / Fact Hash

| stage | programHash | integrityFactHash | sharpFactHash |
| --- | --- | --- | --- |
| processDeactivate | `0x56965bbf56499f3ca2328447a07f18faa48398ff0f5f5dd60fe508e7fb39b8c` | `0x3cb757d38afc91b08d9e03dd7c03584167e72800235475447188ec39f459f81` | `0x7c9c16c4b80a7b93507c5168ddef9ff3f7b1df96493ca830e4471e6596a15e54` |
| addNewKey | `0x61ad9bfc1fc9d3a6ddfce81aab892589dda97e8e432e2ac6df9f008bc71b4cd` | `0x1f90958b31f01b2bf489a0cc0b4f94323340df4b22ba6174b17a8f0738f23b0` | `0xf5fa4ca1e0b4753030a595d9e9eb5a7d388d69cb056bb2e9c88923be1dd163cc` |
| processMessages0 | `0x6d6540adacef60af427027b133a8a5b0d4a40661ec8d3c6ed19460319a4c458` | `0x82b284df81813fcabbece4a8be019eab09cb21008ccadbb969cb5cba7cbe6f` | `0x268af951c91b2ebcb02265c5ac565d205b7cf8de861ad3d2fe845b5cf49fc13d` |
| processMessages1 | `0x6d6540adacef60af427027b133a8a5b0d4a40661ec8d3c6ed19460319a4c458` | `0xe38bbdce7140fe19cd02cb3cc9757c59a20c35020066fa8686c114ddedca91` | `0x72875672db8baeac8ed631c1cfbd20b68613b179ac423b738d85d81411feb81d` |
| tally0 | `0x46f4e3ce5ef38dc13944476010804d52c8c24afca094c24b6b0a608d8591425` | `0x29c5ccfdffca9e759b0e52943e1a8212f1ebba8b055cfe7d1a7ff6c55e9df0` | `0x312b1904925f13acd5d6c8362403455f65ba40a1f6e3f525591cdafab08e7494` |
| tally1 | `0x46f4e3ce5ef38dc13944476010804d52c8c24afca094c24b6b0a608d8591425` | `0x4212a8d812bfcd26ff9bf03ee809f9723bacff3a85368f7282c00d44bb7164c` | `0x86440b0989fdfa047d07da12f313d26a32d2f63cfdca64b47a002f774c74a705` |

## 9. Proof 执行资源

这些数据来自 Atlantic 下载的 `atlantic-result/artifacts/metadata.json`。它们不是链上 gas/fee，但可以用于比较不同 proof 的计算规模。

| stage | n_steps | n_memory_holes | pedersen | poseidon | range_check | ec_op | bitwise |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| processDeactivate | 286518 | 1191 | 30442 | 620 | 1758 | 43 | 12 |
| addNewKey | 48988 | 96 | 5534 | 42 | 147 | 3 | 0 |
| processMessages0 | 308257 | 1158 | 33334 | 473 | 2111 | 31 | 6 |
| processMessages1 | 308285 | 1151 | 33334 | 476 | 2107 | 31 | 6 |
| tally0 | 32115 | 30 | 3506 | 74 | 16 | 0 | 0 |
| tally1 | 32155 | 10 | 3506 | 79 | 16 | 0 | 0 |

## 10. 链上 proof verification 交易与费用

费用数据不是从 `final-query-summary.json` 里直接拿到的，而是通过两步补齐：

1. 调用 Atlantic jobs endpoint：

```text
GET https://atlantic.api.herodotus.cloud/atlantic-query-jobs/{queryId}
```

其中 `PROOF_VERIFICATION` job 的 `context` 里包含 `initial / step1 / ... / final` 每笔链上交易的 `transactionHash`。

2. 对每个 tx hash 调用 Starknet Sepolia RPC：

```text
starknet_getTransactionReceipt
```

读取 receipt 里的 `actual_fee.amount` 和 `actual_fee.unit`。

本次使用的 RPC：

```text
https://starknet-sepolia-rpc.publicnode.com
```

注意：下面的费用是 proof verification 阶段所有链上 step 交易的实际 receipt fee 求和，不只是 `final` 交易。

### 10.1 费用汇总

| stage | tx 数 | 总费用 FRI | 约等于 STRK | proofVerificationJobId |
| --- | ---: | ---: | ---: | --- |
| processDeactivate | 8 | 5125909691878754560 | 5.125909692 | `01KSP26G6GHR2W6EBPNTCENJX9` |
| addNewKey | 8 | 4399873275658073888 | 4.399873276 | `01KSP24T40MAHH6MD0CE4P6SG5` |
| processMessages0 | 9 | 5490943993038677248 | 5.490943993 | `01KSP288DCG9J99SDWK3756G7A` |
| processMessages1 | 9 | 5479706619152048192 | 5.479706619 | `01KSP288GCCDKJ25VKF63KCT80` |
| tally0 | 9 | 3891172820516087328 | 3.891172821 | `01KSP29BANJ878HBGXJN3RXR39` |
| tally1 | 9 | 3931420063883316000 | 3.931420064 | `01KSP26R1G5T8G70HPEGV02Y87` |

### 10.2 processDeactivate tx 明细

| step | tx hash | actual fee | status |
| --- | --- | ---: | --- |
| initial | [0x1c7118ed5f7e82d9cd4f76787973a60d46a7e115300c593be1a42bda09bbbf4](https://sepolia.starkscan.co/tx/0x1c7118ed5f7e82d9cd4f76787973a60d46a7e115300c593be1a42bda09bbbf4) | 3934960963496792608 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step1 | [0x5a2066da3ec8f25d980085a220af2d28ad5e974d6a30cd088ebed253356ccca](https://sepolia.starkscan.co/tx/0x5a2066da3ec8f25d980085a220af2d28ad5e974d6a30cd088ebed253356ccca) | 353287810643632896 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step2 | [0x2fe88ae78e93e7d1006abfc91520abc837f927f88ed414cc569aa4fb2301a90](https://sepolia.starkscan.co/tx/0x2fe88ae78e93e7d1006abfc91520abc837f927f88ed414cc569aa4fb2301a90) | 191321801427695104 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step3 | [0x2918d6fb995aa833b87304892d2b949b46656ea608ae885a94287789cb74fb](https://sepolia.starkscan.co/tx/0x2918d6fb995aa833b87304892d2b949b46656ea608ae885a94287789cb74fb) | 170795789006889216 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step4 | [0x8ca3b42c056e5ac15ae439e1ee8cabb8ccccd07521618d73991aaf15da4df1](https://sepolia.starkscan.co/tx/0x8ca3b42c056e5ac15ae439e1ee8cabb8ccccd07521618d73991aaf15da4df1) | 150269709006889216 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step5 | [0x1aa4f5033ca53e7744a7575c7a38e3caeed5d3b8ed9d1fdc4aeab670f2254f](https://sepolia.starkscan.co/tx/0x1aa4f5033ca53e7744a7575c7a38e3caeed5d3b8ed9d1fdc4aeab670f2254f) | 129103688554130176 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step6 | [0x45b493c46790ff968b4bed41354b8023aef6038560ff3a1efd97490a60dc8b9](https://sepolia.starkscan.co/tx/0x45b493c46790ff968b4bed41354b8023aef6038560ff3a1efd97490a60dc8b9) | 108257716187581184 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| final | [0x7f13204835e2e6bf42f5e0480b9e94367df4c28db3e14f9ec78a0e524712c6f](https://sepolia.starkscan.co/tx/0x7f13204835e2e6bf42f5e0480b9e94367df4c28db3e14f9ec78a0e524712c6f) | 87912213555144160 FRI | SUCCEEDED/ACCEPTED_ON_L2 |

### 10.3 addNewKey tx 明细

| step | tx hash | actual fee | status |
| --- | --- | ---: | --- |
| initial | [0x7e6dbd4d647b90d4cffb21c5dcc058d6e0c9a4249b371b1fe09899d9b1e8e35](https://sepolia.starkscan.co/tx/0x7e6dbd4d647b90d4cffb21c5dcc058d6e0c9a4249b371b1fe09899d9b1e8e35) | 3349058119588608576 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step1 | [0x4168cd3c75da006690b16716c31d24306e3337ab15678b0a2de7f72141de43a](https://sepolia.starkscan.co/tx/0x4168cd3c75da006690b16716c31d24306e3337ab15678b0a2de7f72141de43a) | 283865346362801664 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step2 | [0x4364331f995716ee01cf79849cbeb7d971fc13e9ab34d5adbadad1abb4971c8](https://sepolia.starkscan.co/tx/0x4364331f995716ee01cf79849cbeb7d971fc13e9ab34d5adbadad1abb4971c8) | 181739266362801664 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step3 | [0x78eb4afefa84e514ed8fcf73d3663e65c1056c2b4d92e44a69ce5c065e0872c](https://sepolia.starkscan.co/tx/0x78eb4afefa84e514ed8fcf73d3663e65c1056c2b4d92e44a69ce5c065e0872c) | 160893253585899264 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step4 | [0x4d0ac6abfddb0979c4071636d29c04cbc1352dd821c8bc18f6fb45c42691841](https://sepolia.starkscan.co/tx/0x4d0ac6abfddb0979c4071636d29c04cbc1352dd821c8bc18f6fb45c42691841) | 140047236430329600 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step5 | [0x436cee57bff640bddccd9c60e34be540b8457e6579908af47e511fe0d28b074](https://sepolia.starkscan.co/tx/0x436cee57bff640bddccd9c60e34be540b8457e6579908af47e511fe0d28b074) | 119201156430329600 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step6 | [0x2eb324c460d7162555acb2c46526a32819fc54319bb4c850e15a13658d18f7b](https://sepolia.starkscan.co/tx/0x2eb324c460d7162555acb2c46526a32819fc54319bb4c850e15a13658d18f7b) | 89349122026868480 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| final | [0x4287f63d90bb7ed0bdcf1550219ca47c692b364a97c8309021990a64fa401a0](https://sepolia.starkscan.co/tx/0x4287f63d90bb7ed0bdcf1550219ca47c692b364a97c8309021990a64fa401a0) | 75719774870435040 FRI | SUCCEEDED/ACCEPTED_ON_L2 |

### 10.4 processMessages0 tx 明细

| step | tx hash | actual fee | status |
| --- | --- | ---: | --- |
| initial | [0x4676a537c513dfee2e8f8e5465cd6aedc91f2796e6f7ccf280fec7575f91697](https://sepolia.starkscan.co/tx/0x4676a537c513dfee2e8f8e5465cd6aedc91f2796e6f7ccf280fec7575f91697) | 4037394504923201536 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step1 | [0x7c18131c6526f38f641878e4dfd43cade1f96853fd4e5251bc2e8ef79ddc61d](https://sepolia.starkscan.co/tx/0x7c18131c6526f38f641878e4dfd43cade1f96853fd4e5251bc2e8ef79ddc61d) | 394278913209925632 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step2 | [0x1365b8c70bca8b6598530deb5a08f9c55bf13f20cfc1670b81bf0de6099fc88](https://sepolia.starkscan.co/tx/0x1365b8c70bca8b6598530deb5a08f9c55bf13f20cfc1670b81bf0de6099fc88) | 283832833209925632 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step3 | [0x731638ceb098b8c420f1c0dc3050a3b2a3eb40cdb28ee621384ff52e9166ad](https://sepolia.starkscan.co/tx/0x731638ceb098b8c420f1c0dc3050a3b2a3eb40cdb28ee621384ff52e9166ad) | 181386753209925632 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step4 | [0x67b73546e2160eba6fb75bbc2039b6cb75aeff5ef2d2139d19da0e5e7b0475c](https://sepolia.starkscan.co/tx/0x67b73546e2160eba6fb75bbc2039b6cb75aeff5ef2d2139d19da0e5e7b0475c) | 160540735777391872 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step5 | [0x3cc11a34fe00320649df287c7ab145c59c5e53091145a63ca57ab19aa8108b4](https://sepolia.starkscan.co/tx/0x3cc11a34fe00320649df287c7ab145c59c5e53091145a63ca57ab19aa8108b4) | 139374655777391872 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step6 | [0x403b317cbbce01641e0d7aaffe2b12e6f7f9de675496580fd1c6d7717c5e1f5](https://sepolia.starkscan.co/tx/0x403b317cbbce01641e0d7aaffe2b12e6f7f9de675496580fd1c6d7717c5e1f5) | 109522580581103616 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step7 | [0x9ac238e0dd5e836afab213b9188b4afa39b352bf86dd403dbed2c571c04b31](https://sepolia.starkscan.co/tx/0x9ac238e0dd5e836afab213b9188b4afa39b352bf86dd403dbed2c571c04b31) | 96051860581103616 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| final | [0x304dd92d8e322d3a34726d6143fe0d03fe072997107eab39a07f36fb4a8889b](https://sepolia.starkscan.co/tx/0x304dd92d8e322d3a34726d6143fe0d03fe072997107eab39a07f36fb4a8889b) | 88561155768707840 FRI | SUCCEEDED/ACCEPTED_ON_L2 |

### 10.5 processMessages1 tx 明细

| step | tx hash | actual fee | status |
| --- | --- | ---: | --- |
| initial | [0x63d86a2199b8d354b8d1b9a949027aa76058098ae309e4c6a934995ead63b5b](https://sepolia.starkscan.co/tx/0x63d86a2199b8d354b8d1b9a949027aa76058098ae309e4c6a934995ead63b5b) | 4034662984923201536 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step1 | [0x4cf023ede74ad83f407039391f293392263cc6b8b9b50ce72b409bbc41edf69](https://sepolia.starkscan.co/tx/0x4cf023ede74ad83f407039391f293392263cc6b8b9b50ce72b409bbc41edf69) | 393155073209925632 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step2 | [0x6d06c7d4fe2be301a397bee1594eeaae315fe9bd31de0f171d5d4685480139c](https://sepolia.starkscan.co/tx/0x6d06c7d4fe2be301a397bee1594eeaae315fe9bd31de0f171d5d4685480139c) | 282388993209925632 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step3 | [0x67b6518e8dfd24915b51c9be9f4a5e7062141def6a25c2bffab96123be72bf9](https://sepolia.starkscan.co/tx/0x67b6518e8dfd24915b51c9be9f4a5e7062141def6a25c2bffab96123be72bf9) | 180262975777391872 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step4 | [0x918f53b092fe6e3c3673c22d8664ea02ffba090532093c7822d7c71eea7dd0](https://sepolia.starkscan.co/tx/0x918f53b092fe6e3c3673c22d8664ea02ffba090532093c7822d7c71eea7dd0) | 159416895777391872 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step5 | [0x2bff3495167fedd043d3c37b79ed57c5b259a8c2749e7c13cc2ad5e5cff5de1](https://sepolia.starkscan.co/tx/0x2bff3495167fedd043d3c37b79ed57c5b259a8c2749e7c13cc2ad5e5cff5de1) | 138250900581103616 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step6 | [0x508f3879c0d60e4ac6ad042a1b977948eead8969f9e3506fe39b58c233e6b68](https://sepolia.starkscan.co/tx/0x508f3879c0d60e4ac6ad042a1b977948eead8969f9e3506fe39b58c233e6b68) | 108398740581103616 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step7 | [0x13ad61e7db779ef94f5f8aaf14b0c18562b53019e7ffad9bd203b33698873b4](https://sepolia.starkscan.co/tx/0x13ad61e7db779ef94f5f8aaf14b0c18562b53019e7ffad9bd203b33698873b4) | 94608020581103616 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| final | [0x32c571c54446e838eea3ee80aec1df3b0aab90afe394e3a24afed7ef39e8f7c](https://sepolia.starkscan.co/tx/0x32c571c54446e838eea3ee80aec1df3b0aab90afe394e3a24afed7ef39e8f7c) | 88562034510900800 FRI | SUCCEEDED/ACCEPTED_ON_L2 |

### 10.6 tally0 tx 明细

| step | tx hash | actual fee | status |
| --- | --- | ---: | --- |
| initial | [0x16282f7e9be759c97b9c3974f356cfb00ad883af58ed8685dd6dd35462d4b67](https://sepolia.starkscan.co/tx/0x16282f7e9be759c97b9c3974f356cfb00ad883af58ed8685dd6dd35462d4b67) | 2457834006358265056 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step1 | [0x70f91582be7c8f85f4a5749fd4340a7ec32da1f9e7d489e8f8ff8a93838391](https://sepolia.starkscan.co/tx/0x70f91582be7c8f85f4a5749fd4340a7ec32da1f9e7d489e8f8ff8a93838391) | 391391380581103616 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step2 | [0x670ae4216bad0957569c53717c0074b6c7bf1af600ac4deb49639c07e38c2d5](https://sepolia.starkscan.co/tx/0x670ae4216bad0957569c53717c0074b6c7bf1af600ac4deb49639c07e38c2d5) | 280945300581103616 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step3 | [0x776ef29629cc557fd54404068faf1b879d3fe22b74c3f3e945a08198ed62bdd](https://sepolia.starkscan.co/tx/0x776ef29629cc557fd54404068faf1b879d3fe22b74c3f3e945a08198ed62bdd) | 178499220581103616 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step4 | [0x5d5988e87abd7377192ac89da8515fa4e6283f72dea276b0d4fe9d1c5ea33f7](https://sepolia.starkscan.co/tx/0x5d5988e87abd7377192ac89da8515fa4e6283f72dea276b0d4fe9d1c5ea33f7) | 157653228695193344 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step5 | [0x42b3efc2624005a71b756ff2962adc9af2373a57e73d293569572b615c093a7](https://sepolia.starkscan.co/tx/0x42b3efc2624005a71b756ff2962adc9af2373a57e73d293569572b615c093a7) | 136487216801937920 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step6 | [0x58c853b8b7a5d6b4f445176afa76f6403159a8b93f104778cf80bd91b45a92a](https://sepolia.starkscan.co/tx/0x58c853b8b7a5d6b4f445176afa76f6403159a8b93f104778cf80bd91b45a92a) | 106635056801937920 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step7 | [0x4f9190e218e782470ce6ec510cb79ec23a1b7ee5913d9b25880b14328a40be9](https://sepolia.starkscan.co/tx/0x4f9190e218e782470ce6ec510cb79ec23a1b7ee5913d9b25880b14328a40be9) | 93164446044417280 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| final | [0x67236cff105b38ac82538b41fb1858997a11a748dee8b4f146a32c060c4ed10](https://sepolia.starkscan.co/tx/0x67236cff105b38ac82538b41fb1858997a11a748dee8b4f146a32c060c4ed10) | 88562964071024960 FRI | SUCCEEDED/ACCEPTED_ON_L2 |

### 10.7 tally1 tx 明细

| step | tx hash | actual fee | status |
| --- | --- | ---: | --- |
| initial | [0x841b02e648507b35aac0196b8cff0898fe4c4963d1deab2c53e337bf1958bc](https://sepolia.starkscan.co/tx/0x841b02e648507b35aac0196b8cff0898fe4c4963d1deab2c53e337bf1958bc) | 2470579523496792608 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step1 | [0x66d08c44f0092f66411cf9941bc08effd65807badb06633bbd8c09c2a216c2e](https://sepolia.starkscan.co/tx/0x66d08c44f0092f66411cf9941bc08effd65807badb06633bbd8c09c2a216c2e) | 395000521427695104 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step2 | [0x3e8dee45f759ac01d8357f26b18a4f9dd53a791c98d2e64ad392c3f240f51c9](https://sepolia.starkscan.co/tx/0x3e8dee45f759ac01d8357f26b18a4f9dd53a791c98d2e64ad392c3f240f51c9) | 284554509006889216 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step3 | [0x5b1f4e87018d830e8e311df4b1231fdfa760cfb2ad467a5d9e52d75048001b7](https://sepolia.starkscan.co/tx/0x5b1f4e87018d830e8e311df4b1231fdfa760cfb2ad467a5d9e52d75048001b7) | 182428429006889216 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step4 | [0x39dc36ce4d0f868776a6f4b6ef1c1bcf1c0b000080a767b89032b5e9118a9b0](https://sepolia.starkscan.co/tx/0x39dc36ce4d0f868776a6f4b6ef1c1bcf1c0b000080a767b89032b5e9118a9b0) | 161582408554130176 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step5 | [0x7b4736afddb5f7303441932c0c8f7b5f85fbe607dd7092d6ef349280e436639](https://sepolia.starkscan.co/tx/0x7b4736afddb5f7303441932c0c8f7b5f85fbe607dd7092d6ef349280e436639) | 140736436187581184 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step6 | [0x525f7c619c6cbdbdc29f31b50c0465c726ecc7e60c9b6f6aae01d0dd142a792](https://sepolia.starkscan.co/tx/0x525f7c619c6cbdbdc29f31b50c0465c726ecc7e60c9b6f6aae01d0dd142a792) | 110884276187581184 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| step7 | [0x1fbb410baf01133022c063c112865e44efc258323c0ab4adee3b52c6f257f9b](https://sepolia.starkscan.co/tx/0x1fbb410baf01133022c063c112865e44efc258323c0ab4adee3b52c6f257f9b) | 97093633209925632 FRI | SUCCEEDED/ACCEPTED_ON_L2 |
| final | [0x3aa5db6da69c852c5193861082834fbd73cf3029ddf89dc4c227d3977344c85](https://sepolia.starkscan.co/tx/0x3aa5db6da69c852c5193861082834fbd73cf3029ddf89dc4c227d3977344c85) | 88560326805831680 FRI | SUCCEEDED/ACCEPTED_ON_L2 |

## 11. 需要注意的测试实现细节

当前 native Cairo stage 是固定批大小：

- deactivate stage 固定 3 个 slot
- processMessages 每批固定 3 个 slot

而本次真实场景是：

- 2 个真实 deactivate
- 5 条真实 vote message

因此 fixture 里包含：

- 1 个 invalid padding deactivate slot
- 1 个 invalid padding vote slot

这些 padding slot 是为了满足当前 native stage 固定批大小，不代表真实用户行为，不改变最终 raw tally result。

## 12. 最终判断

这个测试已经按标准 AMACI round 语义串起来：

```text
signup -> deactivate -> addNewKey -> vote -> processMessages -> tally
```

并验证了两个关键语义：

1. 已 deactivate 的 old key 后续投票会被 processMessages 判为无效。
2. 通过 addNewKey 生成的新 `stateIndex = 5` 可以正常投票，并进入最终 tally。

最终结果 `[1, 0, 0, 0, 10]` 与测试设计一致。
