FROM registry.access.redhat.com/ubi9/python-312

LABEL name="harness-eval" \
      summary="Static analysis for AI code agent configurations" \
      description="Scans AI agent setups (Claude Code, Cursor, Copilot, Gemini CLI, OpenCode) for security, quality, and best-practice issues." \
      url="https://github.com/redhat-community-ai-tools/harness-eval" \
      io.k8s.display-name="harness-eval" \
      io.openshift.tags="ai,security,static-analysis,tekton" \
      license="Apache-2.0"

USER 0

COPY . /opt/app-root/src/harness-eval

RUN cd /opt/app-root/src/harness-eval && \
    pip install --no-cache-dir ".[yara,bash-ast,tiktoken]" && \
    chgrp -R 0 /opt/app-root && chmod -R g=u /opt/app-root && \
    mkdir -p /workspace && chgrp 0 /workspace && chmod g=u /workspace

ENV HOME=/tmp

USER 1001

WORKDIR /workspace

ENTRYPOINT ["harness-eval"]
CMD ["--help"]
