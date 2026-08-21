import { defineConfig } from "astro/config";
import icon from "astro-icon";

export default defineConfig({
  output: "static",
  trailingSlash: "always",
  integrations: [
    icon({
      include: {
        "fa6-brands": ["github", "telegram", "facebook"],
        "fa6-solid": ["envelope", "house", "box-archive", "address-card", "folder-open", "tags"],
      },
    }),
  ],
});
