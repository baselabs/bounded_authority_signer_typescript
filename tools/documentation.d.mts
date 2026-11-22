export interface Sample {
  kind: "file" | "file-dom" | "run" | "run-dom" | "types" | "setup" | "notebook";
  line: number;
  code: string;
  fileName: string;
  source: string;
  output?: string;
}
export function parse(markdown: string, source?: string): Sample[];
export function discover(root: string): Sample[];
export function files(root: string): string[];
export function anchors(markdown: string): Set<string>;
export function links(markdown: string): string[];
