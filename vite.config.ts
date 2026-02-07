import { defineConfig } from "vite";
import dts from "vite-plugin-dts";
import { resolve } from "path";

export default defineConfig({
  plugins: [
    dts({
      include: ["src/**/*"],
      rollupTypes: true,
    }),
  ],
  build: {
    lib: {
      entry: {
        index: resolve(__dirname, "src/index.ts"),
        sveltekit: resolve(__dirname, "src/adapters/sveltekit/index.ts"),
      },
      formats: ["es", "cjs"],
    },
    rollupOptions: {
      external: [
        "openid-client",
        "jwt-decode",
        "@mssfoobar/sds-client",
        "@sveltejs/kit",
        /^node:/,
      ],
      output: {
        preserveModules: false,
      },
    },
    target: "ES2022",
    sourcemap: true,
    minify: false,
  },
});
