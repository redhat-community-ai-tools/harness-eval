# OpenShift Pipelines Integration

Run harness-eval as a security gate in OpenShift Pipelines (Tekton). Scans AI agent configurations for security, quality, and best-practice issues as a pipeline step.

## Prerequisites

- OpenShift cluster with the OpenShift Pipelines operator installed
- `oc` CLI logged in to the cluster

## Container Image

harness-eval ships a UBI9-based container image compatible with OpenShift's `restricted-v2` SCC (arbitrary UID, root group).

### Build from source

```bash
podman build -t harness-eval:dev -f Containerfile .
```

### Push to internal registry

```bash
REGISTRY=$(oc registry info)
oc new-project harness-eval-demo  # or use an existing project
podman login "$REGISTRY" -u $(oc whoami) -p $(oc whoami -t) --tls-verify=false
podman tag harness-eval:dev "$REGISTRY/harness-eval-demo/harness-eval:dev"
podman push "$REGISTRY/harness-eval-demo/harness-eval:dev" --tls-verify=false
```

## Quickstart

Apply the Tekton Task and Pipeline, then create a PipelineRun:

```bash
oc apply -f tekton/task-harness-eval.yaml
oc apply -f tekton/pipeline-harness-eval.yaml
oc create -f tekton/pipelinerun-example.yaml
```

Watch the logs:

```bash
oc get pipelinerun -w
# or, if tkn CLI is available:
tkn pipelinerun logs --last -f
```

## Tekton Task Parameters

The `harness-eval` Task accepts the following parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image` | (internal registry) | Container image for harness-eval |
| `path` | `.` | Subdirectory within the workspace to scan |
| `commands` | `lint,security` | Comma-separated commands to run |
| `enforce` | `strict` | `strict` (fail on findings), `advisory` (report only), `off` (skip) |
| `format` | `terminal` | Output format: `terminal`, `json`, `sarif` |
| `recursive` | `false` | Recursively search subdirectories for agent configs |
| `exclude` | (empty) | Comma-separated glob patterns to exclude |

## Task Results

After a run completes, the Task emits two results:

| Result | Values | Description |
|--------|--------|-------------|
| `verdict` | `CLEAN`, `NEEDS_WORK`, `BLOCKED`, `UNKNOWN` | Overall assessment |
| `grade` | `A` through `F` | Report card grade |

## Pipeline Structure

The sample pipeline (`tekton/pipeline-harness-eval.yaml`) has two tasks:

1. **fetch-source**: clones the target repository using the cluster's `git-clone` Task
2. **harness-eval**: runs lint + security scan on the cloned source

The pipeline fails if harness-eval finds issues (when `enforce=strict`). This is the gate: a finding exits non-zero, the step fails, the PipelineRun fails.

## Scanning a Different Repository

Edit the PipelineRun or create a new one:

```yaml
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  generateName: scan-my-repo-
spec:
  pipelineRef:
    name: harness-eval-scan
  params:
    - name: repo-url
      value: https://github.com/your-org/your-repo.git
    - name: revision
      value: main
    - name: enforce
      value: strict
  workspaces:
    - name: shared-workspace
      emptyDir: {}
```

## Air-Gapped Clusters

The `lint` and `security` commands are fully offline. They need no API keys, no internet egress, and no external service calls. Token counting falls back to a chars/4 heuristic when tiktoken cannot download its BPE file. This makes harness-eval suitable for air-gapped and restricted environments.

Only the `review` command (LLM-based rubric review) requires an API key and network access, and it is not included in the default Tekton Task commands.

## Workspace Storage

The sample PipelineRun uses `emptyDir: {}` for the workspace, which requires no PVC provisioning. For larger repositories or when you need to preserve scan artifacts, use a `volumeClaimTemplate` with a StorageClass allowed by your cluster:

```yaml
  workspaces:
    - name: shared-workspace
      volumeClaimTemplate:
        spec:
          storageClassName: aws-ebs  # adjust for your cluster
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 1Gi
```

## Troubleshooting

**Image pull errors**: Verify the image is in a registry the cluster can reach. For internal registry, use `image-registry.openshift-image-registry.svc:5000/<namespace>/harness-eval:<tag>`.

**Permission errors**: The container runs as an arbitrary UID under `restricted-v2`. If you see file permission issues, rebuild the image (the Containerfile sets group-writable permissions).

**PVC errors**: Some clusters enforce StorageClass or label requirements on PVCs. Use `emptyDir: {}` to avoid PVC issues entirely, or check your cluster's storage admission policies.
