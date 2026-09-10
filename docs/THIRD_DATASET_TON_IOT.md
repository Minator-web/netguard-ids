# Locked evaluation on ToN-IoT Network

NetGuard 1.0 evaluates the previously locked 0.9 preprocessing decision on a
third dataset. ToN-IoT was created for IoT/IIoT security research and its
network data were collected in PCAP, Zeek log, and CSV formats. Dataset source:
<https://research.unsw.edu.au/projects/toniot-datasets>.

## Pre-registered comparison

The experiment loads `artifacts/robust-preprocessing.joblib`, which was created
before ToN-IoT evaluation. It evaluates:

- `standard`: the original scaling baseline
- the pipeline already stored as `selected_on_source_validation`

No pipeline is trained and no transformer, feature set, model, or threshold is
selected on ToN-IoT. The comparison of the locked source-selected pipeline
against the baseline is therefore specified before target labels are scored.

## Feature mapping

| NetGuard feature | ToN-IoT field or derivation |
| --- | --- |
| duration_seconds | `duration` |
| forward_packets | `src_pkts` |
| backward_packets | `dst_pkts` |
| forward_bytes | `src_bytes` |
| backward_bytes | `dst_bytes` |
| packets_per_second | `(src_pkts + dst_pkts) / duration` |
| forward_bytes_per_second | `src_bytes / duration` |
| backward_bytes_per_second | `dst_bytes / duration` |
| forward_iat_mean_ms | unavailable; source-fitted median imputation |
| backward_iat_mean_ms | unavailable; source-fitted median imputation |

Source/destination direction is treated as forward/backward direction. This is
an explicit approximation. Only eight of the ten model inputs are directly
available or defensibly derived, so the two IAT features are passed as missing
and filled by each already-fitted source imputer.

## Data placement and execution

Place the network train/test CSV at:

```text
data/TON_IoT_Train_Test_Network.csv
```

Then run:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli evaluate-ton
```

If the downloaded filename or directory differs, provide it explicitly:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.ml_cli evaluate-ton --ton "D:\datasets\train_test_network.csv"
```

The adapter reads the CSV in chunks and writes:

- `reports/ton-evaluation.json`
- `reports/ton-evaluation.md`

Use `--max-rows` only as a software check. A limited run must not be reported as
the full third-dataset result.

## Interpretation limits

ToN-IoT differs from UNSW-NB15 and CIC-IDS2017 in traffic composition,
collection tooling, environment, attacks, and labels. Missing IAT fields also
make this a partial-feature transfer test. Report these limitations beside any
improvement or failure.
