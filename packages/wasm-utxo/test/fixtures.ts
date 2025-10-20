import * as fs from "fs/promises";
export async function getFixture(path: string, defaultValue: unknown): Promise<unknown> {
  try {
    return JSON.parse(await fs.readFile(path, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") {
      await fs.writeFile(path, JSON.stringify(defaultValue, null, 2));
      throw new Error(`Fixture not found at ${path}, created a new one`);
    }
  }
}
