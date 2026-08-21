import { getCollection, type CollectionEntry } from "astro:content";

export type Post = CollectionEntry<"posts">;

export async function getSortedPosts(): Promise<Post[]> {
  const posts = await getCollection("posts", ({ data }) =>
    import.meta.env.PROD ? !data.draft : true,
  );

  return posts.sort(
    (a, b) => b.data.published.getTime() - a.data.published.getTime(),
  );
}

export function postUrl(post: Post) {
  return `/posts/${post.slug}/#reading-start`;
}

export function formatDate(date: Date, style: "short" | "archive" = "short") {
  if (style === "archive") {
    return new Intl.DateTimeFormat("en", { day: "2-digit", month: "short" })
      .format(date)
      .toUpperCase();
  }

  return new Intl.DateTimeFormat("vi-VN", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  })
    .format(date)
    .replaceAll("/", ".");
}

export function readingTime(body: string) {
  const words = body.trim().split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.ceil(words / 220));
}

export function postExcerpt(post: Post) {
  if (post.data.description) return post.data.description;

  const plain = post.body
    .replace(/^---[\s\S]*?---/, "")
    .replace(/```[\s\S]*?```/g, "")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[#>*_`~-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  return plain.length > 165 ? `${plain.slice(0, 162).trim()}…` : plain;
}
