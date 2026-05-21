/**
 * plugin-tui 전용 build script.
 *
 * bun build CLI 가 plugin flag 미지원 → programmatic Bun.build 사용.
 * @opentui/solid 의 JSX 는 bun 자체 transform 으로 jsxDev 호출 → opentui/solid
 * 의 jsx-dev-runtime 이 .d.ts 만이라 runtime export 없음 → 에러.
 *
 * 해결: @opentui/solid/bun-plugin (default export = solidTransformPlugin,
 * Babel + babel-preset-solid + @babel/preset-typescript) 박아서 file 마다
 * Babel transform 후 bundle.
 */

import solidTransformPlugin from "@opentui/solid/bun-plugin"

const result = await Bun.build({
  entrypoints: ["src/plugin-tui.tsx"],
  outdir: "dist",
  target: "bun",
  format: "esm",
  minify: true,
  external: [
    "@opencode-ai/plugin",
    "@opencode-ai/sdk",
    "@opentui/core",
    "@opentui/solid",
    "solid-js",
  ],
  plugins: [solidTransformPlugin],
})

if (!result.success) {
  console.error("plugin-tui build FAILED")
  for (const msg of result.logs) console.error(msg)
  process.exit(1)
}

for (const output of result.outputs) {
  const sizeKb = (output.size / 1024).toFixed(2)
  console.log(`  ${output.path}  ${sizeKb} KB`)
}
