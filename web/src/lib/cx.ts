// Adapted for Clavis: local utility imports and project formatting.
// Source: https://raw.githubusercontent.com/tremorlabs/tremor/ca4d588f47820ff3d514d37fa4ee08a4222dec11/src/utils/cx.ts
// Tremor cx [v0.0.0]

import clsx, { type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cx(...args: ClassValue[]) {
  return twMerge(clsx(...args))
}
