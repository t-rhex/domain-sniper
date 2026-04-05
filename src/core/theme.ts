/**
 * Theme system inspired by OpenCode's dark theme
 * Uses a stepped grayscale palette with accent colors
 */

export const palette = {
  // Grayscale steps (dark to light)
  step1: "#0a0a0a",   // Deepest background
  step2: "#141414",   // Panel background
  step3: "#1e1e1e",   // Elevated surface
  step4: "#282828",   // Subtle borders
  step5: "#323232",   // Borders
  step6: "#3c3c3c",   // Active borders
  step7: "#464646",   // Muted elements
  step8: "#505050",   // Disabled text
  step9: "#6e6e6e",   // Placeholder text
  step10: "#8c8c8c",  // Muted text
  step11: "#b0b0b0",  // Secondary text
  step12: "#eeeeee",  // Primary text

  // Accent colors
  green: "#00e88f",
  greenDim: "#0a3d2a",
  blue: "#5c9cf5",
  blueDim: "#1a2d4a",
  yellow: "#f5c542",
  yellowDim: "#3d3018",
  red: "#f55c5c",
  redDim: "#3d1a1a",
  orange: "#f5955c",
  orangeDim: "#3d2818",
  purple: "#9d7cd8",
  purpleDim: "#2a1f3d",
  cyan: "#56d4dd",
  cyanDim: "#1a3335",
} as const;

export const theme = {
  // Backgrounds
  background: palette.step1,
  backgroundPanel: palette.step2,
  backgroundElevated: palette.step3,

  // Text
  text: palette.step12,
  textSecondary: palette.step11,
  textMuted: palette.step10,
  textPlaceholder: palette.step9,
  textDisabled: palette.step8,

  // Borders
  border: palette.step5,
  borderActive: palette.step6,
  borderSubtle: palette.step4,

  // Semantic
  primary: palette.green,
  primaryDim: palette.greenDim,
  secondary: palette.blue,
  secondaryDim: palette.blueDim,
  warning: palette.yellow,
  warningDim: palette.yellowDim,
  error: palette.red,
  errorDim: palette.redDim,
  info: palette.cyan,
  infoDim: palette.cyanDim,
  accent: palette.purple,
  accentDim: palette.purpleDim,
  pending: palette.orange,
  pendingDim: palette.orangeDim,
} as const;

// ─── Border characters ───────────────────────────────────

export const borders = {
  rounded: {
    topLeft: "╭",
    topRight: "╮",
    bottomLeft: "╰",
    bottomRight: "╯",
    horizontal: "─",
    vertical: "│",
    topT: "┬",
    bottomT: "┴",
    leftT: "├",
    rightT: "┤",
    cross: "┼",
  },
  heavy: {
    topLeft: "┏",
    topRight: "┓",
    bottomLeft: "┗",
    bottomRight: "┛",
    horizontal: "━",
    vertical: "┃",
    topT: "┳",
    bottomT: "┻",
    leftT: "┣",
    rightT: "┫",
    cross: "╋",
  },
  splitLeft: {
    topLeft: "",
    topRight: "",
    bottomLeft: "",
    bottomRight: "",
    horizontal: " ",
    vertical: "┃",
    topT: "",
    bottomT: "",
    leftT: "",
    rightT: "",
    cross: "",
  },
} as const;

// ─── Status styling ──────────────────────────────────────

export type DomainStatus = "pending" | "checking" | "available" | "expired" | "taken" | "error" | "registered" | "registering";

export function statusStyle(status: DomainStatus) {
  switch (status) {
    case "pending":
      return { icon: "○", fg: theme.textDisabled, label: "PENDING" };
    case "checking":
      return { icon: "◆", fg: theme.warning, label: "CHECKING" };
    case "available":
      return { icon: "●", fg: theme.primary, label: "AVAILABLE" };
    case "expired":
      return { icon: "◈", fg: theme.pending, label: "EXPIRED" };
    case "taken":
      return { icon: "✕", fg: theme.error, label: "TAKEN" };
    case "registered":
      return { icon: "◉", fg: theme.secondary, label: "REGISTERED" };
    case "registering":
      return { icon: "◌", fg: theme.info, label: "REGISTERING" };
    case "error":
      return { icon: "!", fg: theme.error, label: "ERROR" };
  }
}
