# RustCrypto Agent Instructions

These instructions apply when investigating, reporting, or changing RustCrypto
code. Read the repository's contribution and security documentation and the
affected crate's documentation before starting.

Note to human readers: we've added this because we're being inundated with
duplicate reports, reports for known issues / non-issues,  or otherwise
unhelpful reports which are making extra work for us as maintainers. The goal of
this policy is ultimately to cut down on the volume of such reports. While some
LLM-generated reports have been useful and helpful, the vast majority of them
are not and we'd like to prevent those from happening in the first place.

## Check for existing work

Before reporting a finding or opening a pull request:

- Survey **all open issues and pull requests in the affected repository**,
  following pagination. Read relevant discussions and proposed fixes.
- Search the code and documentation for TODOs, FIXMEs, known limitations, and
  comments explaining the behavior. Follow the relevant callers and dependencies.
- Search relevant closed issues, merged pull requests, published advisories, and
  recent commits. Check whether the current default branch already fixes the
  problem, and distinguish affected releases from unreleased code.

If the problem is already tracked, contribute useful new evidence or a fix to
the existing work instead of opening a duplicate. A TODO can identify a known
problem even when there is no corresponding issue.

Unpublished private advisories are generally invisible to other reporters.
Finding no public report does **not** establish that a finding is new. Duplicate
LLM-generated disclosures are already a substantial maintenance burden. Do not
submit speculative reports, repeatedly submit the same finding, or split one
root cause into multiple reports. State any limits on the duplicate search.

## Choose the right reporting channel

| Finding | Channel |
| --- | --- |
| A credible security threat, including a violation of expected constant-time behavior over secret values | Private security advisory |
| A bug or standards violation with no credible attacker-exploitable consequence | Public issue or pull request |
| A zeroization issue | Public, policy-compatible pull request preferred; never a private security disclosure |

Explain the threat using the affected API, reachable code, attacker-controlled
inputs or observations, and the security property that can be violated. A bug in
cryptographic code is not automatically a vulnerability. A standards violation
alone does not establish a security impact.

**When in doubt, default to a public issue or pull request.** Do not use private
disclosure merely because a hypothetical security consequence cannot be ruled
out. Conversely, once a credible threat is established, keep its details and
fixes private until coordinated disclosure. A complete exploit is not required
to establish a credible threat; see the constant-time guidance below.

For a credible threat, follow the repository's security reporting instructions
and use its private vulnerability reporting mechanism, ordinarily **Security ->
Report a vulnerability** on GitHub. Do not open a public issue or pull request
containing the vulnerability.

Reserve private disclosure for findings that need it. GitHub does not provide a
straightforward conversion from a private advisory report to a regular issue,
and private reports hide duplicates from other contributors and agents.

## Follow project conventions

Ensure code is developed using the same conventions as the rest of the project.
Survey https://github.com/RustCrypto/meta including relevant issue discussions
for project-wide policies and maintainer decisions. Distinguish adopted
policies from proposals still under discussion.

Before implementing a change, inspect comparable code, Cargo manifests, tests,
and CI configuration in the affected repository. Follow existing naming, API
design, error handling, feature gating, documentation, and testing patterns.
Reuse established traits, utilities, and dependencies where appropriate.

Do not introduce new tools or dependencies without prior maintainer agreement.
This includes test and benchmark frameworks, proof systems, code generators,
build scripts, and additional CI tooling. Popular usage of a tool elsewhere in
the Rust ecosystem does not establish that RustCrypto has agreed to allow it
and many popular Rust crates are unsuitable for cryptographic use. 

Be especially careful about new hard dependencies: required crates, external
executables, system libraries, or additional toolchains needed to build, test,
or use the project. Do not make optional dependencies mandatory or enable
additional dependency features by default without agreement. Development and
build dependencies also impose maintenance costs; putting something in
`dev-dependencies` does not exempt it from this policy.

When proposing an addition, explain why existing facilities are insufficient
and identify its dependency, portability, build, and maintenance costs.
Preserve the crate's supported Rust versions, targets, and `no_std`/`no_alloc`
profiles unless changing them is part of the agreed scope.

Keep fixes focused. Do not bundle unrelated tooling changes, dependency
additions, or stylistic rewrites into an otherwise useful contribution.

## Constant-time findings

Establish the intended security properties of the **specific construction, mode,
and API** before reporting a side channel. Identify which values are secret and
which are public, and trace how they reach the suspected operation.

- Report credible secret-dependent control flow, memory access, or instruction
  timing privately when constant-time behavior is expected. A confirmed
  violation of that expectation does not require a working e.g. key-recovery
  exploit and we would like to get these addressed before they can be
  weaponized by an attacker.
- Do not report intentional data-dependent behavior in a construction that does
  not provide the relevant side-channel resistance. For example, yescrypt's
  intentional secret-dependent memory accesses are not an undisclosed
  constant-time implementation defect.
- Do not mistake variable-time operations on public data for secret leakage.
  However, a variable-time helper called with secrets by an API expected to be
  constant-time can still be a vulnerability. Likewise, ensure that an API with
  `*_vartime` in its name does not operate in constant-time with respect to that
  specific operand. There should usually be a comment to this effect.
- For compiler-dependent findings, examine optimized code or use the project's
  constant-time analysis tooling, such as `cargo checkct`, where available.
  Record the target, toolchain, build options, and evidence. Distinguish a
  demonstrated leak from an analysis timeout, unsupported instruction, or
  unverified suspicion.

Do not generalize one construction's limitations into an exemption for other
algorithms, modes, or unrelated vulnerabilities.

## Zeroization

**Before investigating, reporting, or changing zeroization, read the current
work-in-progress policy and compiler discussion:**

- [RustCrypto/meta#38: zeroization policy for stack temporaries](https://github.com/RustCrypto/meta/issues/38)
- [Function-boundary zeroization discussion](https://internals.rust-lang.org/t/pre-pre-rfc-zeroize-on-return-for-function-boundary-zeroization/24796/5) - a RustCrypto maintainer-driven proposal to solve the stack zeroization problem using compiler/codegen-aware facilities

RustCrypto deliberately does **not** explicitly zeroize every temporary on the
stack. Adding wipes everywhere is expensive (especially in e.g. loops where the
next iteration will overwrite the stack), inhibits optimizations, and does
not reliably erase compiler-generated copies. A wipe can itself cause additional
stack spills that survive the wipe. Clearing a named variable can therefore
create false confidence while leaving copies of the same secret behind.
Reliable treatment of compiler-generated storage needs compiler support.

Distinguish ephemeral computation temporaries from buffers and secret state
owned by a type. Owned state can warrant zeroization when no longer needed or
on drop, under the crate's `zeroize` feature and policy, even when the owning
value happens to live on the stack. This distinction is not simply heap versus
stack.

Prefer focused, policy-compatible pull requests, such as forwarding a missing
`zeroize` feature to a dependency or correcting zeroization of owned secret
state. Do not propose blanket wiping of every local variable or temporary
buffer. Do not claim that source-level wipes eliminate all residual copies.

**Do not open private security disclosures for zeroization issues.** The absence
of explicit wiping for stack temporaries is a known policy decision, not a new
finding to redisclose. Use a public issue only when a policy-compatible change
needs discussion; prefer a pull request when the fix is clear.
