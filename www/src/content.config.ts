import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const docs = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/docs" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    order: z.number().default(99),
    section: z.enum(["start", "guide", "reference"]).default("guide"),
  }),
});

const useCases = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/use-cases" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    audience: z.string(),
    pack: z.string().optional(),
    order: z.number().default(99),
  }),
});

const packs = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/packs" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    effect: z.string(),
    packId: z.string(),
    order: z.number().default(99),
  }),
});

export const collections = { docs, useCases, packs };
