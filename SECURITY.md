# Security policy

## Reporting a vulnerability in Caziel

Please open a private security advisory on GitHub (Security → Report a vulnerability) rather than a public issue. I aim to reply within a week.

## What Caziel does and doesn't touch

- `scan`, `fix`, `robot` and `checks` only read local files and write to the output path you give. They make no network calls and need no AWS credentials.
- `fix` refuses to overwrite a directory that isn't a Caziel fleet directory.
- `watch` only reads the event file or stdin you give it and prints verdicts. It doesn't block, publish or call AWS.
- The website sends nothing anywhere unless you paste an Anthropic API key into the chat. The key stays in that tab's memory and is only sent to `api.anthropic.com`.
- `snapshot` runs read-only `ros2` commands (`node list`, `node info`, `param dump`) on the machine where it runs.

## Using the output

Caziel is a security analysis tool. Its energy numbers are estimates for prioritising work. They are not a substitute for ISO 10218 / ISO/TS 15066 validation, a risk assessment by a qualified safety engineer, or safety-rated hardware limits.
