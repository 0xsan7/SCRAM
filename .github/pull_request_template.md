name: Pull request
description: Every change needs evidence that it does what it claims
labels: []
body:
  - type: markdown
    attributes:
      value: |
        ## The bar for this repository

        A claim in a pull request description is not evidence. The
        acceptance criterion for anything here is that it was **executed
        end to end with real inputs** -- not that it compiles, not that a
        test exists, not that the tool appears in a list.

        Three rules from `CONTRIBUTING.md` that CI cannot check for you:

        1. **A test that does not call the thing it is named for is not a
           test of it.** A test that cannot fail is worse than no test,
           because it gets counted.
        2. **Break the guard before trusting it.** If you add a check, show
           it red by breaking the code it guards. A green check that was
           never seen failing is an assumption.
        3. **Do not hand-author fixtures when a real one exists.** Real
           lockfiles find bugs that minimal reproductions do not (D24).

  - type: textarea
    id: what
    attributes:
      label: What does this change?
      description: What the reader will see differently after merging.
    validations:
      required: true

  - type: textarea
    id: evidence
    attributes:
      label: How do you know it works?
      description: >
        Paste the command and its actual output. Real numbers from a real
        run, not a description of what the run should produce. If this is
        a bug fix, the failing case before and the passing case after.
      placeholder: |
        ```
        $ go test ./internal/resolve/ -run TestNpmArrayLicense -count=1
        ok  github.com/0xsan7/scram/internal/resolve  1.204s
        ```
    validations:
      required: true

  - type: textarea
    id: red
    attributes:
      label: Show the check going red
      description: >
        For any new guard, test, or check: what did you break, and what
        did you see? Paste the failing output. If a new test passes both
        before and after your change, it is not testing your change and
        needs deleting or rewriting.
      placeholder: |
        ```
        $ # revert the fix
        $ go test ./internal/vuln/ -run TestDedupe -count=1
        --- FAIL: TestDedupeDoesNotInflateCVSS (0.00s)
            dedupe_cvss_test.go:64: CVSSv3 = 8.1, want at most 7.2
        ```
    validations:
      required: true

  - type: dropdown
    id: kind
    attributes:
      label: What kind of change is this?
      options:
        - Bug fix
        - New feature
        - Resolver or parser change
        - Documentation only
        - CI, release, or tooling
        - Dependency update
    validations:
      required: true

  - type: checkboxes
    id: gates
    attributes:
      label: Gates
      description: All four run in CI; tick what you ran locally.
      options:
        - label: "`gofmt -l ./cmd ./internal` is empty"
        - label: "`go test ./... -count=1` passes"
        - label: "`go vet ./...` is clean"
        - label: "`golangci-lint run` is clean"
        - label: "Secret scan is clean (`/tmp/scan/gitleaks detect --log-opts=--all` or the CI job)"
        - label: "If you touched a resolver: the corpus check passes (`go run ./cmd/corpus-check`)"
        - label: "If you touched DECISIONS.md: `python3 scripts/gen_decision_index.py` and `python3 scripts/gen_adrs.py` both regenerated"
        - label: "If you touched action.yml: `python3 scripts/check_action_metadata.py` passes"

  - type: checkboxes
    id: invariants
    attributes:
      label: Invariants
      description: >
        These are the properties this project must not lose. Tick only
        what is actually true of your change.
      options:
        - label: "Fail-closed behaviour is unchanged: a resolver that resolves zero components from a declaring file is still an operational error, not a clean result"
        - label: "I did not add a path that can report CLEAN when data could not be retrieved"
        - label: "New code does not weaken the silent-zero guard in internal/scan or internal/resolve"
        - label: "If I added an ecosystem or resolver, I updated `TestResolverRegistry` (it asserts the current ecosystem count) and the `osvEcosystem` map -- without that second one, vulnerabilities are skipped silently"

  - type: textarea
    id: docs
    attributes:
      label: Documentation affected
      description: >
        README, LIMITATIONS.md, DECISIONS.md (and `scripts/gen_adrs.py`),
        `docs/STATUS.md`, `docs/BLOCKED.md`, or none of them. If a
        behaviour changed, a document claiming the old behaviour is now a
        false claim, and this project would rather hear about it than ship
        it.
