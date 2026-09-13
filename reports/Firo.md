## firoorg/firo
Private audit / coordinated disclosure - Target: [firoorg/firo](https://github.com/firoorg/firo)

Firo is a privacy-focused L1 with Spark as its current shielded-payment protocol. This report records
a Spark-related node-availability finding submitted privately to the Firo team on June 1, 2026. The
team confirmed the report was valid, but classified it as already identified and patched before the
disclosure reached them.

- **Reported target commit:** `cd7018813b7f4d8136c06572faeb6fe9d6e0c9de`
- **Relevant prior fix:** `89456e21cc1bfa4daf687f53770bf9bf84cda0ad` in PR #1805
- **Fix release:** `v0.14.16.1`
- **Original encrypted artifact:** `SPARK_P2P_NODE_CRASH_REPORT.md.asc`
- **Artifact SHA256:** `a8292c578a9279ed613652348a876f2ed70ec271b18a1f921aa8fa2794b198ff`
- **Firo signature artifact SHA256:** `78618954fc713352fe89b3d8ee2ce507156f530fcbaaca3fd35edebae085dc4e`

**Team disposition.** Firo's response stated that the report was valid, but that the underlying issue
had already been identified and patched before disclosure. The team pointed to public commit
`89456e21`, which added the decisive zero-length guard and the regression test
`empty_input_vectors_rejected`, and to the later release `v0.14.16.1`. The entry below keeps the
technical record without claiming bounty eligibility.

**Severity note.** The Firo response did not assign a final paid severity; it confirmed validity and
prior-fix status. The issue was reported as a node-availability vulnerability, and under Firo's bounty
language vulnerabilities that impact individual nodes or must be carefully exploited map to the Major
tier. Because Firo treated this as prior-fixed / duplicate, this report records that as researcher
severity analysis rather than as a Firo-awarded severity.

---

### [Valid duplicate] Malformed Spark proof/vector dimensions could crash node-side validation

**Target:** Spark proof validation paths around `src/libspark/chaum.cpp`, reached through Spark spend
processing in the Firo node.

**Weakness:** CWE-20 (improper input validation) / CWE-248 (uncaught exception)
**Disposition:** Valid, but prior-fixed before disclosure

**Finding description and impact**

Malformed Spark proof/vector dimensions could reach validation in a shape where empty input vectors
were treated as passing the basic dimension check. The dangerous condition was a zero-sized proof
input: equality between several empty vectors is not the same as a semantically valid proof shape.
Without an explicit zero-length rejection, verifier-side processing could proceed into an invalid
state and crash node-side validation.

The public patch Firo identified added the missing guard in `src/libspark/chaum.cpp`:

```cpp
if (n == 0 || !(T.size() == n && proof.A2.size() == n && proof.t1.size() == n)) {
```

It also added a focused regression test in `src/libspark/test/chaum_test.cpp`:

```cpp
BOOST_AUTO_TEST_CASE(empty_input_vectors_rejected)
```

That test captures the intended invariant directly: empty Spark proof input vectors must be rejected
before verifier logic consumes them.

**Disclosure timeline**

| Date | Event |
| ---- | ----- |
| 2026-05-03 | Public PR #1805 commit `89456e21` added the `n == 0` guard and `empty_input_vectors_rejected` test. |
| 2026-05-26 | The reported target commit `cd7018813` was created. |
| 2026-06-01 | PR #1805 merged as `4dfdd12e`; its parent was `cd7018813`. |
| 2026-06-03 | The fix shipped in Firo `v0.14.16.1`. |
| 2026-08-26 | PR #1913 added direct `w == 0` rejection as additional hardening. |

The parent relationship was the deciding detail: the vulnerable target commit existed, but the public
fix branch already contained the relevant guard before the disclosure was sent.

**Proof of Concept**

The original report and reproduction material were submitted privately as a PGP-encrypted artifact.
This portfolio entry does not republish the crash PoC; it preserves the technical summary, timeline,
hashes, and public patch evidence.

The signature packet supplied with the team response identified issuer fingerprint
`0186454D63E83D85EF91DE4E1290A1D0FA7EE109`, matching Firo's published PGP fingerprint for
`reuben@firo.org`. The detached signature cannot be fully verified without the exact signed plaintext,
so it is retained as supporting disclosure-record evidence rather than standalone proof of the email
body.

**Impact**

Node availability impact. A malformed Spark proof/vector shape should be rejected at the trust
boundary; instead, the vulnerable path could reach validation with impossible dimensions and crash
node-side processing. The report did not claim inflation, theft of funds, anonymity-set collapse, or
remote code execution.

**Recommended mitigation steps**

Reject impossible Spark proof and spend dimensions before any verifier or transaction-processing
logic consumes them. Keep regression tests close to the relevant verifier paths so empty vector and
zero-input cases remain pinned.

Firo's referenced patches implement that direction by adding the `n == 0` guard for Chaum proof
validation and later hardening Spark V2 spend construction with direct `w == 0` rejection.

**References**

- Firo PR #1805: [https://github.com/firoorg/firo/pull/1805](https://github.com/firoorg/firo/pull/1805)
- Fix commit `89456e21`: [https://github.com/firoorg/firo/commit/89456e21cc1bfa4daf687f53770bf9bf84cda0ad](https://github.com/firoorg/firo/commit/89456e21cc1bfa4daf687f53770bf9bf84cda0ad)
- PR #1805 merge commit `4dfdd12e`: [https://github.com/firoorg/firo/commit/4dfdd12e5bb1c2a197e7d3b5e2401bff3edb57c5](https://github.com/firoorg/firo/commit/4dfdd12e5bb1c2a197e7d3b5e2401bff3edb57c5)
- Reported target commit `cd7018813`: [https://github.com/firoorg/firo/commit/cd7018813b7f4d8136c06572faeb6fe9d6e0c9de](https://github.com/firoorg/firo/commit/cd7018813b7f4d8136c06572faeb6fe9d6e0c9de)
- Firo `v0.14.16.1` release: [https://github.com/firoorg/firo/releases/tag/v0.14.16.1](https://github.com/firoorg/firo/releases/tag/v0.14.16.1)
- Firo PR #1913: [https://github.com/firoorg/firo/pull/1913](https://github.com/firoorg/firo/pull/1913)
- Firo vulnerability bounty program: [https://firo.org/guide/bounty-program.html](https://firo.org/guide/bounty-program.html)
