// Integration contract for a Next.js Route Handler.
// The production AAK service remains external to the model-facing application.
type Proposal = {
  transactionId: string;
  action: string;
  resource: string;
  parameters: Record<string, unknown>;
  maximumEffect: Record<string, number>;
  evidence: string[];
};

export async function requestAuthorizedExecution(proposal: Proposal) {
  const response = await fetch(process.env.AAK_GATEWAY_URL!, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${process.env.APP_TO_AAK_IDENTITY_TOKEN}`,
    },
    body: JSON.stringify(proposal),
    cache: "no-store",
  });

  if (!response.ok) throw new Error("Action denied by authority kernel");
  return response.json();
}

