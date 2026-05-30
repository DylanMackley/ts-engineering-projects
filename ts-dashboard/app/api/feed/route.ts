import { NextResponse } from "next/server";

export async function GET() {
  try {
    const apiKey = process.env.URLSCAN_API_KEY;

    if (!apiKey) {
      return NextResponse.json(
        { error: "URLSCAN_API_KEY not configured" },
        { status: 500 }
      );
    }

    const res = await fetch(
  "https://urlscan.io/api/v1/search/?q=domain:vercel.app&size=20",
      {
        headers: {
          "Content-Type": "application/json",
          "API-Key": apiKey,
        },
        signal: AbortSignal.timeout(8000),
        next: { revalidate: 60 },
      }
    );

if (!res.ok) {
  return NextResponse.json(
    { error: `URLScan returned ${res.status}` },
    { status: 502 }
  );
}

    const data = await res.json();
    const results = data.results ?? [];

    const urls = results
      .map((r: any) => ({
        url:       r?.page?.url ?? r?.task?.url ?? null,
        domain:    r?.page?.domain ?? null,
        submitted: r?.task?.time ?? null,
        country:   r?.page?.country ?? null,
        server:    r?.page?.server ?? null,
      }))
      .filter((r: any) =>
        r.url &&
        r.url.includes("vercel.app") &&
        r.url.startsWith("http")
      )
      .filter((r: any, i: number, arr: any[]) =>
        arr.findIndex((x: any) => x.url === r.url) === i
      );

    return NextResponse.json({
      count: urls.length,
      fetchedAt: new Date().toISOString(),
      urls,
    });

  } catch (err) {
    return NextResponse.json(
      { error: "Feed fetch failed" },
      { status: 500 }
    );
  }
}
