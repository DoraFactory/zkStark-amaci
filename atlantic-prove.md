# AMACI Native Stone / Atlantic 探索记录

Date: 2026-05-17

这份文档按实际探索顺序记录：为什么要把 AMACI 从非 native 密码学迁移到
Starknet/STARK native 版本，迁移后我们验证了什么，为什么继续走 Stone，Stone
本地路径遇到了什么问题，以及为什么当前选择 Atlantic/Herodotus 服务路径。

当前 Atlantic query:

```text
01KRSWP39Q5MGPDWX6SE7SNN36
https://www.herodotus.cloud/en/atlantic/01KRSWP39Q5MGPDWX6SE7SNN36
```

当前状态：

```text
status: DONE
step: PROOF_VERIFICATION
result: PROOF_VERIFICATION_ON_L2
network: TESTNET
chain: L2
sharpProver: stone
layout: recursive_with_poseidon
jobSize: S
isFactMocked: false
isProofMocked: false
createdAt: 2026-05-17T02:36:46.654Z
completedAt: 2026-05-17T02:45:59.917Z
```

关键输出：

```text
transactionId: 01KRSWP9P8BANP6X7A9J8S4N46
programHash: 0x26059ab7b74d91be472b4974914eac5156c7883e84a665c9755b67b25c6137d
integrityFactHash: 0x105d6c825149ccb9aec7557078fe38b6f1a12163fd99ee68e78e255f33871e3
sharpFactHash: 0x3f3f5260c7a07b7f110224f7b4caa1b73e9dd5934300d6d55efb7e2035efbe8b
```

## 1. 最初目标：把 AMACI 迁移成 Starknet/STARK 友好的 native 版本

原 AMACI 证明逻辑里包含较重的非 Starknet-native 密码学组件，例如 BN254
Poseidon、SHA-256 风格的哈希路径，以及和 EVM/circom 体系更贴近的数据绑定方式。
这些东西在 Cairo/STARK 里能实现，但代价很高，不适合后续要在 Starknet 生态里
低成本证明和验证。

所以我们明确了一个目标：不是机械复刻原来的 hash，而是做一个适合
Starknet/STARK 的 AMACI 新版本。

核心思路：

- 用 Starknet/Cairo 更友好的 native hash/commitment 取代重型 BN254/SHA 路径。
- 保持 AMACI 的协议语义仍然成立：创建 key、处理投票消息、deactivate、tally。
- 让电路产物更适合后续 Stone/Integrity/Starknet 验证路径。
- 优先证明“新体系下 AMACI 仍然 work”，而不是执着于保留旧 hash 实现。

## 2. native 化之后，本地证明已经跑通

迁移后，我们先用本地 Scarb/Stwo 路径验证 native AMACI 的正确性和可证明性。

成功跑通的命令：

```sh
npm run prove:all-native-split-small -- \
  --tally-input fixtures/tally-small/000000.json \
  --out-dir /data/zkstark-amaci-proofs/native-20260516-113915/all-native-split
```

关键结果：

```text
Proof runs: 56/56 verified
Wall time: 9:29.50
Max RSS: 18,574,716 KB
```

覆盖范围包括：

- `tally-native`
- `add-new-key-native`
- `process-messages-native-split`
- `process-deactivate-native-split`
- message/decrypt/ecdh/signature/core/boundary 等 split 子电路

这个阶段证明：native AMACI 的本地证明关系是完整的，56 个 proof run 都可以生成并
验证。

但这里也有一个关键限制：Scarb/Stwo 的 `proof.json` 是本地 proof artifact，不是
当前 Starknet 应用层 Integrity verifier 直接可提交的格式。因此它只能说明
native 迁移方向正确，还不能说明 proof 已经可以上链验证。

## 3. 为什么继续跑 Stone

Starknet 当前应用层可用的 Herodotus Integrity verifier 主要围绕 Stone proof
格式工作。因此，如果目标是把 AMACI proof 提交到 Starknet 上验证，下一步必须把
native AMACI 跑到 Stone 路径上。

也就是说：

- Scarb/Stwo 本地证明：用于验证 native AMACI 关系正确。
- Stone proof：用于接近 Starknet/Integrity 当前可用的上链验证格式。

所以我们开始跑 Stone。

## 4. Stone 路径第一次问题：旧 tally 太重

一开始尝试非 native 的 `tally_votes_stone`，即旧 tally 逻辑走 Stone。

这个路径能生成 AIR，但参数非常大：

```text
n_steps: 67,108,864
STARK degree bound: 2^30
```

本地 `cpu_air_prover` 在 64GB 机器上被 OOM kill。

这说明：如果继续使用旧的非 native tally，即使改成 Stone proof，也会因为 trace
规模过大导致本地证明不可用，后续服务端证明成本也会非常高。

这个结果反过来验证了 native 化的必要性：不是为了代码风格好看，而是为了让 Stone
证明规模降下来。

## 5. native tally 的 Stone proof 已经显著变轻

之后改用 `tally-native` 跑 Stone。

成功命令：

```sh
export STONE_OUT=/data/zkstark-amaci-proofs/stone-native-tally-20260516-144921

CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib \
npm run stone:air:tally -- \
  --out-dir "$STONE_OUT/stone-air"

npm run stone:prove:tally -- \
  --air-run "$STONE_OUT/stone-air/stone-air-run.json" \
  --out-dir "$STONE_OUT/stone-proof-integrity-v2"
```

关键结果：

```text
n_steps: 131,072
STARK degree bound: 2^21
Stone proof generation: ~20 seconds
Max RSS: ~6.2 GB
Verified proof successfully
```

和旧 tally 相比：

- trace steps 从 `67,108,864` 降到 `131,072`
- degree bound 从 `2^30` 降到 `2^21`
- 资源消耗从 OOM 降到本地可跑

所以 native 化对 Stone 路径是实质性优化。

## 6. 本地 Integrity split calldata 路径的问题

Stone proof 跑通后，我们尝试把本地 Stone proof 转成 Herodotus Integrity split
calldata。

成功序列化后得到：

```text
Stone proof JSON: 1.1M / 1,106,989 bytes
Integrity split calldata JSON: 788K / 806,724 bytes
Calldata felts: 10,804
Step files: 4
Verifier config hash:
0x7889bb7939fd1da7bd2d96376db9ca037dcee666914b8368d9221fb4e7feef0
```

split 后每笔 calldata 大小：

```text
initial: 8662 felts
step1:   640 felts
step2:   568 felts
step3:   496 felts
step4:   292 felts
final:   156 felts
```

问题集中在 `initial`：

- Starknet 当前单笔 transaction calldata limit 是 `5000 felts`。
- `initial = 8662 felts`，超过上限。
- 后面的 step/final 都很小，但 initial 这笔无法直接用普通交易提交。

因此，本地 split calldata 直接上链这条路暂时不可行。

## 7. 降低安全参数不是正式解法

我们试过降低 FRI query 数，例如把 `n_queries` 改到 `4`。

结果：

```text
Calldata felts: 8482
initial: 7751 felts
```

虽然有所下降，但 initial 仍然超过 5000。而且降低 FRI query 数会降低 proof
安全性，不适合作为正式路径。

所以这个实验只说明：

- initial 主要不是 query chunks 导致的；
- 靠降低 query 数不能解决；
- 更不能为了塞进 calldata limit 牺牲安全参数。

## 8. 中间遇到的 serializer/annotation 问题

在本地 Integrity split calldata 路径中，我们还遇到过几类格式问题：

- Stone proof 缺 verifier annotations 时，swiftness 缺 OODS 数据。
- prover-only annotations 会导致 OODS 解析不完整。
- Stone 参数 profile 不匹配时会出现 OODS evaluation mismatch。
- optional `split-calldata/full` 文件里可能出现非 felt 内容，之前会误伤包装流程。

这些问题已经逐步定位并修复：

- 使用 Integrity-compatible Stone params。
- proof 生成后运行 verifier，并把 verifier annotations merge 回 `stone-proof.json`。
- 对 optional `full` 文件做容错，不让它阻塞 split calldata package。

这些修复让本地 pipeline 更完整，但它们不能解决 Starknet 单笔 calldata 上限。

## 9. 为什么现在改用 Atlantic

Atlantic/Herodotus 的官方路径不是让我们把本地 `stone-proof.json` 或 split calldata
直接上传，而是提交：

- Cairo1 `programFile`
- Cairo1 Rust VM `inputFile`
- proving/verification 参数

然后由 Atlantic 服务端完成：

- trace generation
- Stone proof generation
- L2 Integrity verification
- 返回 query status、transaction/fact/verification metadata

这条路径正好解决当前本地路径的主要问题：

1. 不需要我们自己把 `initial` split calldata 作为普通交易塞进 Starknet。
2. 不需要降低安全参数。
3. 使用的是 Herodotus 当前支持的服务入口。
4. 成功后可以拿到 AMACI wrapper 需要绑定的 fact/program/output/verifier metadata。

因此，当下最合理的路线是：

```text
native Cairo1 program/input
  -> Atlantic trace/proof/L2 verification
  -> registered fact / verification metadata
  -> AMACI wrapper 做最终状态更新检查
```

## 9.1 安全边界：提交给 Atlantic 会暴露什么，如何确认它按我们的输入运行

这里要区分两个问题：

- proof 正确性：Atlantic 不能随便伪造一个能通过 Integrity verifier 的 proof。
- witness 隐私：Atlantic 作为 prover 服务，会看到我们提交的 `inputFile`。

`programFile` 是 Cairo1 Sierra 程序，一般不包含投票隐私，但会暴露当前电路实现。
`inputFile` 是 Cairo VM 的运行输入，本质上包含这个证明需要的 witness。对当前
`tally-native` 来说，它包含：

- public fields：`packed_vals`、`state_commitment`、`current_tally_commitment`、
  `new_tally_commitment`、`input_hash`
- witness：state root/salt、state leaves、Merkle path、votes、current results、
  result root salts 等

因此，如果某些 witness 在生产环境里必须对 prover 保密，就不能把这份
`inputFile` 交给外部服务；这种情况下需要自托管 Stone/Integrity prover，或者重新
设计证明拆分，使外部服务只接触可公开数据。

对后续 `process-messages` / `process-deactivate` 电路还要更谨慎，因为这些 witness
可能包含 coordinator private key、shared key、decrypted command、signature
witness、state leaf/path 等更敏感内容。提交前必须逐个电路审计
`cairo-input.json` 和 `cairo1-run-args.txt`，确认哪些字段会被 Atlantic 看到。

我们如何确认 Atlantic 是按我们的程序和输入跑的：

1. 提交前固定本地 bundle 哈希。

   `atlantic-query-bundle.json` 会记录：

   - `programFile.path`
   - `programFile.sha256`
   - `inputFile.path`
   - `inputFile.sha256`
   - `inputFile.feltCount`
   - `layout/result/network/sharpProver`

   这些用于证明“我们提交的是哪一份 program/input”。

2. Query 完成后保存 Atlantic 返回的 metadata。

   至少保存：

   - `atlanticQueryId`
   - `transactionId`
   - `integrityFactHash` 或 `verificationHash`
   - `programHash`
   - `layout`
   - `result`
   - `network`
   - `sharpProver`

3. 下载 proof/metadata 后本地复算。

   Atlantic 文档说明 `PROOF_VERIFICATION_ON_L2` 查询可以下载 proof file。拿到
   proof 后，本地重新计算/检查：

   - proof 内 public memory output
   - `program_hash`
   - `output_hash`
   - `fact_hash`

   这些必须和 Atlantic status、Integrity/Satellite 查询结果一致。

4. 链上 wrapper 不能只相信 Atlantic API 返回值。

   AMACI wrapper 最终应该在 Starknet 上检查：

   - fact/verification 已在 Integrity/Satellite 中注册
   - `mockFactHash=false`，不能接受 mocked fact
   - child program hash 是我们预期的 native AMACI 程序
   - public output 是我们预期的 state transition / tally commitment
   - verifier config、layout、hasher、Stone version、memory verification、安全位数满足策略
   - 当前 AMACI state 未被 replay/stale proof 覆盖

5. 如果是 bootloaded proof，要按 bootloaded fact 规则处理。

   Integrity 文档说明，bootloaded 程序的顶层 `program_hash` 可能是 bootloader
   program hash，child program hash 会出现在 bootloader output 中。因此 wrapper
   不能只比较顶层 `program_hash`，还要按 Integrity 的 bootloaded fact/verification
   hash 规则绑定 child program hash 和 public output。

结论：Atlantic 可以解决“本地 split calldata 初始交易过大”和“服务端生成/注册
proof”的问题，但它不是隐私隔离层。我们可以通过 proof/fact/output/config 的链上
校验确认它没有替换证明语义；但如果 `inputFile` 里有生产敏感 witness，提交给
Atlantic 本身就是一次数据披露。

## 10. Atlantic 当前怎么用

我们已经把本地 Stone AIR 产物导出成 Atlantic 接受的 bundle。

输入：

```sh
export STONE_OUT=/data/zkstark-amaci-proofs/stone-native-tally-20260516-144921
export ATLANTIC_OUT="$STONE_OUT/atlantic-query"
```

源文件：

```text
$STONE_OUT/stone-air/stone-air-run.json
```

导出的 Atlantic 文件：

```text
$ATLANTIC_OUT/tally_votes_native_stone.program.sierra.json
$ATLANTIC_OUT/tally_votes_native_stone.input.txt
$ATLANTIC_OUT/atlantic-query-bundle.json
$ATLANTIC_OUT/submit-atlantic-query.sh
```

导出命令：

```sh
cd ~/zkStark-amaci
git pull

npm run export:atlantic-query -- \
  --stone-air-run "$STONE_OUT/stone-air/stone-air-run.json" \
  --out-dir "$ATLANTIC_OUT" \
  --result PROOF_VERIFICATION_ON_L2 \
  --network TESTNET \
  --layout recursive_with_poseidon \
  --declared-job-size S \
  --external-id "amaci-native-tally-$(date +%Y%m%d-%H%M%S)" \
  --text
```

提交命令：

```sh
export ATLANTIC_API_KEY=...

"$ATLANTIC_OUT/submit-atlantic-query.sh" \
  | tee "$ATLANTIC_OUT/submit-response.json"
```

首次提交遇到 MIME type 问题：

```json
{
  "message": "PROGRAM_FILE_SHOULD_BE_JSON",
  "additionalData": {
    "expected": "application/json",
    "received": "application/octet-stream"
  }
}
```

原因是 curl 默认把 `programFile` 发成 `application/octet-stream`。已经通过 commit
修复：

```text
de92fae Set Atlantic multipart file types
```

现在提交脚本显式发送：

```text
programFile=@...;type=application/json
inputFile=@...;type=text/plain
```

修复后提交成功：

```json
{"atlanticQueryId":"01KRSWP39Q5MGPDWX6SE7SNN36"}
```

## 11. 当前 Atlantic query 参数

```text
endpoint=https://atlantic.api.herodotus.cloud/atlantic-query
declaredJobSize=S
sharpProver=stone
layout=recursive_with_poseidon
cairoVm=rust
cairoVersion=cairo1
result=PROOF_VERIFICATION_ON_L2
mockFactHash=false
network=TESTNET
programHash=
programFile=@$ATLANTIC_OUT/tally_votes_native_stone.program.sierra.json;type=application/json
inputFile=@$ATLANTIC_OUT/tally_votes_native_stone.input.txt;type=text/plain
```

`programHash` 为空是刻意的：第一次提交让 Atlantic 根据上传的 program file 处理。
后续如果服务返回可复用的 program hash，再考虑复用。

## 12. 如何继续查看状态

推荐用 repo 工具保存 status、summary，并下载 artifacts：

```sh
export ATLANTIC_QUERY_ID=01KRSWP39Q5MGPDWX6SE7SNN36

npm run atlantic:fetch-query -- \
  --query-id "$ATLANTIC_QUERY_ID" \
  --out-dir "$ATLANTIC_OUT/result" \
  --download-artifacts \
  --text
```

这会写入：

```text
$ATLANTIC_OUT/result/status.json
$ATLANTIC_OUT/result/final-query-summary.json
$ATLANTIC_OUT/result/atlantic-query-result.json
$ATLANTIC_OUT/result/artifacts/proof.json
$ATLANTIC_OUT/result/artifacts/metadata.json
$ATLANTIC_OUT/result/artifacts/program.cairo1.json
$ATLANTIC_OUT/result/artifacts/input.cairo1.txt
...
```

也可以直接用 curl：

```sh
export ATLANTIC_QUERY_ID=01KRSWP39Q5MGPDWX6SE7SNN36

curl -s \
  -H "api-key: $ATLANTIC_API_KEY" \
  "https://atlantic.api.herodotus.cloud/atlantic-query/$ATLANTIC_QUERY_ID" \
  | tee "$ATLANTIC_OUT/status.json" \
  | jq '.atlanticQuery | {
      id,
      status,
      step,
      transactionId,
      integrityFactHash,
      sharpFactHash,
      programHash,
      layout,
      chain,
      result,
      network,
      sharpProver,
      errorReason,
      createdAt,
      completedAt
    }'
```

循环轮询：

```sh
while true; do
  curl -s \
    -H "api-key: $ATLANTIC_API_KEY" \
    "https://atlantic.api.herodotus.cloud/atlantic-query/$ATLANTIC_QUERY_ID" \
    | tee "$ATLANTIC_OUT/status.json" >/dev/null

  jq -r '.atlanticQuery | "status=\(.status) step=\(.step) tx=\(.transactionId) error=\(.errorReason)"' \
    "$ATLANTIC_OUT/status.json"

  STATUS=$(jq -r '.atlanticQuery.status' "$ATLANTIC_OUT/status.json")
  [ "$STATUS" = "DONE" ] && break
  [ "$STATUS" = "FAILED" ] && break
  sleep 30
done
```

Console:

```text
https://www.herodotus.cloud/en/atlantic/01KRSWP39Q5MGPDWX6SE7SNN36
```

需要用提交这个 query 的同一 Herodotus 账号/钱包登录才能看详情。

## 13. DONE 之后要保存什么

如果 query 进入 `DONE`，保存：

```sh
jq '.atlanticQuery | {
  id,
  status,
  transactionId,
  integrityFactHash,
  sharpFactHash,
  programHash,
  layout,
  chain,
  result,
  network,
  sharpProver,
  errorReason
}' "$ATLANTIC_OUT/status.json" \
  | tee "$ATLANTIC_OUT/final-query-summary.json"
```

后续 AMACI wrapper 需要检查：

- fact hash 或 verification hash 已注册
- program hash 是预期 native tally program
- public output 是预期 tally public output
- verifier config / layout / hasher / security bits 满足策略
- 当前 AMACI state 没有被 replay 或 stale proof 覆盖

只有这些检查通过后，wrapper 才能把 tally proof 结果用于更新 AMACI 状态。

## 14. 目前结论

当前工作已经完成了三个关键阶段：

1. AMACI native 化并本地完整证明。
2. native tally Stone proof 本地生成和验证。
3. Atlantic-compatible query 成功提交。

剩余关键工作：

1. 等待 Atlantic query 完成。
2. 保存返回的 fact/program/transaction metadata。
3. 对接 AMACI wrapper 的 fact binding。
4. 继续把其他 native split 电路也按同样方式导出/提交/绑定。
