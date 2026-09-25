# A3/A4 local performance measurement

This is one WSL2/Linux measurement, not a general performance claim. It covers
the password-v3 baseline, A3 X25519 HPKE, A4 ML-KEM-768, A4 slot updates, and
legacy-v3 root rotation.

## Conditions

- Host: AMD Ryzen 7 5700X, 8 visible CPUs; WSL2 on Linux.
- RAM: 15 GiB. `/tmp` was a 7.9 GiB tmpfs with 7.2 GiB available before the run.
- Build: optimized `target/release/lvau-cli`; password slots used the Fast
  Argon2id profile.
- Inputs: 1 MiB and 256 MiB synthetic `os.urandom` data. Fixtures were prepared
  before timing in a temporary `/tmp` directory; the benchmark removes them.
- Runs: three per operation and size; table values are medians. Wall time uses
  `perf_counter_ns` around the CLI process; GNU `time` supplies CPU% and max RSS.
  Decrypt outputs were compared byte-for-byte with the input.
- CPU% can exceed 100% because GNU `time` reports aggregate CPU across cores.

Reproduce after a release build:

```sh
cargo build --locked --workspace --release
python3 scripts/benchmark-v3-operations.py
```

The measurements include CLI startup and output persistence. Fixture generation
and setup are outside the measured runs. A4 rewrap operations still scan and
authenticate every payload frame, then copy the ciphertext and verify the
staged artifact; root rotation decrypts and encrypts the complete payload.

## Median results

| Operation | Size | Wall (s) | CPU (%) | Max RSS (KiB) | MiB/s | Output bytes |
|---|---:|---:|---:|---:|---:|---:|
| v2 encrypt | 1 MiB | 0.019759 | 100 | 21,028 | 50.6 | 1,048,769 |
| v2 decrypt | 1 MiB | 0.022766 | 100 | 21,140 | 43.9 | 1,048,576 |
| v2 verify | 1 MiB | 0.021328 | 100 | 21,268 | 46.9 | 0 |
| password-v3 encrypt | 1 MiB | 0.020855 | 94 | 20,944 | 48.0 | 1,048,719 |
| password-v3 decrypt | 1 MiB | 0.020577 | 94 | 21,136 | 48.6 | 1,048,576 |
| password-v3 verify | 1 MiB | 0.021241 | 100 | 21,064 | 47.1 | 0 |
| A3 X25519 encrypt | 1 MiB | 0.005825 | 100 | 7,532 | 171.7 | 1,048,744 |
| A3 X25519 decrypt | 1 MiB | 0.004779 | 100 | 7,340 | 209.3 | 1,048,576 |
| A3 X25519 verify | 1 MiB | 0.005045 | 100 | 7,264 | 198.2 | 0 |
| A4 ML-KEM encrypt | 1 MiB | 0.004610 | 100 | 7,244 | 216.9 | 1,049,888 |
| A4 ML-KEM decrypt | 1 MiB | 0.005684 | 100 | 7,296 | 175.9 | 1,048,576 |
| A4 ML-KEM verify | 1 MiB | 0.004736 | 100 | 7,248 | 211.1 | 0 |
| A4 add ML-KEM | 1 MiB | 0.035518 | 97 | 21,460 | 28.2 | 1,051,172 |
| A4 add X25519 | 1 MiB | 0.034640 | 97 | 21,568 | 28.9 | 1,050,092 |
| A4 remove ML-KEM | 1 MiB | 0.035891 | 97 | 21,288 | 27.9 | 1,049,979 |
| A4 remove X25519 | 1 MiB | 0.038007 | 100 | 21,424 | 26.3 | 1,051,172 |
| A4 change password | 1 MiB | 0.050236 | 100 | 21,344 | 19.9 | 1,049,979 |
| legacy-v3 root rotation | 1 MiB | 0.040604 | 97 | 21,240 | 24.6 | 1,048,719 |
| v2 encrypt | 256 MiB | 0.366288 | 166 | 83,128 | 698.9 | 268,439,731 |
| v2 decrypt | 256 MiB | 0.373450 | 168 | 82,952 | 685.5 | 268,435,456 |
| v2 verify | 256 MiB | 0.238475 | 199 | 84,124 | 1,073.5 | 0 |
| password-v3 encrypt | 256 MiB | 0.429286 | 99 | 21,112 | 596.3 | 268,439,681 |
| password-v3 decrypt | 256 MiB | 0.420278 | 99 | 20,952 | 609.1 | 268,435,456 |
| password-v3 verify | 256 MiB | 0.316990 | 99 | 21,164 | 807.6 | 0 |
| A3 X25519 encrypt | 256 MiB | 0.631049 | 99 | 7,452 | 405.7 | 268,439,706 |
| A3 X25519 decrypt | 256 MiB | 0.706684 | 99 | 7,352 | 362.3 | 268,435,456 |
| A3 X25519 verify | 256 MiB | 0.531583 | 100 | 7,448 | 481.6 | 0 |
| A4 ML-KEM encrypt | 256 MiB | 0.616575 | 99 | 7,296 | 415.2 | 268,440,850 |
| A4 ML-KEM decrypt | 256 MiB | 0.586072 | 99 | 7,428 | 436.8 | 268,435,456 |
| A4 ML-KEM verify | 256 MiB | 0.506985 | 100 | 7,320 | 504.9 | 0 |
| A4 add ML-KEM | 256 MiB | 0.822400 | 100 | 21,428 | 311.3 | 268,442,134 |
| A4 add X25519 | 256 MiB | 0.835458 | 100 | 21,596 | 306.4 | 268,441,054 |
| A4 remove ML-KEM | 256 MiB | 0.853056 | 99 | 21,372 | 300.1 | 268,440,941 |
| A4 remove X25519 | 256 MiB | 0.833784 | 99 | 21,272 | 307.0 | 268,442,134 |
| A4 change password | 256 MiB | 0.822095 | 100 | 21,436 | 311.4 | 268,440,941 |
| legacy-v3 root rotation | 256 MiB | 0.884049 | 99 | 21,180 | 289.6 | 268,439,681 |

## 256 MiB median wall time

Scale: 40 columns = 0.884 s.

```text
v2-encrypt               ################# 0.366s
v2-decrypt               ################# 0.373s
v2-verify                ########### 0.238s
v3-password-encrypt      ################### 0.429s
v3-password-decrypt      ################### 0.420s
v3-password-verify       ############## 0.317s
a3-x25519-encrypt        ############################# 0.631s
a3-x25519-decrypt        ################################ 0.707s
a3-x25519-verify         ######################## 0.532s
a4-mlkem-encrypt         ############################ 0.617s
a4-mlkem-decrypt         ########################### 0.586s
a4-mlkem-verify          ####################### 0.507s
a4-add-mlkem             ##################################### 0.822s
a4-add-x25519            ###################################### 0.835s
a4-remove-mlkem          ####################################### 0.853s
a4-remove-x25519         ###################################### 0.834s
a4-change-password       ##################################### 0.822s
legacy-v3-root-rotate    ######################################## 0.884s
```

This single-host microbenchmark is useful as a local regression reference only.
Three runs and tmpfs I/O do not establish general cross-platform performance.
