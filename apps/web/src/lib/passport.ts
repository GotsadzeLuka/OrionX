export type Award = {
  recordId: string;
  name: string;
  category: string;
  dateEarned: string;
  description: string;
  badgeCode: string;
};
export type PassportVersion = {
  revocation?: {state: string; finalizedAt: string | null; message: string} | null;
  credentialStatus?: string;
  version: number;
  state: string;
  verificationCode: string;
  pageCount: number;
  skillAwardCount: number;
  isLatest: boolean;
  createdAt: string;
  finalizedAt: string | null;
  issuerTrust: string;
  cluster: string;
  awards: Award[];
};
export type Passport = {
  official: boolean;
  /** Independently verified institutional issuer trust, not just a Devnet entry. */
  issuerTrust?: "BTU_CONFIRMED" | "DEMO" | "UNCONFIRMED" | "UNAUTHORIZED";
  blockchainRegistration?: "REGISTERED" | "UNKNOWN" | "PENDING";
  onChainRevocation?: "VALID" | "REVOKED" | "UNKNOWN";
  documentIntegrity?: "NOT_CHECKED" | "MATCH" | "MISMATCH";
  status: string;
  passportId: string | null;
  workspaceId: string | null;
  universityVerified: boolean;
  account: { email: string | null };
  counts: { skills: number; badges: number; versions: number };
  originalIssueDate: string | null;
  student: {
    firstName: string;
    lastName: string;
    program: string;
    educationLevel: string;
  } | null;
  latest: PassportVersion | null;
  pending: boolean;
};
export const dateLabel = (date: string) =>
  new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  }).format(new Date(date));


/** Issuance is independent of the university endorsement flag.
 * A finalized Devnet demo must remain viewable even when official=false.
 */
export function isIssuedPassport(passport: Passport | null | undefined): boolean {
  return !!passport?.latest && !!passport.passportId;
}
