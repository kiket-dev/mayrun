# Shell-hook demo

Scripted capture: [`shell-hook-demo.tape`](./shell-hook-demo.tape) (VHS).

```text
$ mayrun init --force
$ eval "$(mayrun shell-hook)"
$ rm -rf /
mayrun: denied by policy
  rule_id: pack.dangerous.rm-root
  reason:  Destructive delete targeting root filesystem
…
```

Under ~30s, no audio. Rendered GIF: [`shell-hook-demo.gif`](./shell-hook-demo.gif) (embedded on README / mayrun.dev). Regenerate with `vhs docs/assets/shell-hook-demo.tape`.
