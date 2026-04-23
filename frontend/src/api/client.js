const API_BASE = "/api";

export async function createAnalyzeJob({
  source,
  file,
  designDoc,
  configDoc,
  testDoc,
  algorithm,
  mode,
}) {
  const form = new FormData();
  if (source) form.append("source", source);
  if (file) form.append("file", file);
  if (designDoc) form.append("design_doc", designDoc);
  if (configDoc) form.append("config_doc", configDoc);
  if (testDoc) form.append("test_doc", testDoc);
  if (algorithm) form.append("algorithm", algorithm);
  if (mode) form.append("mode", mode);
  // FormData에는 size 속성이 없으므로, 입력 존재 여부로 전송 방식 결정
  const useForm = !!(file || source || designDoc || configDoc || testDoc || algorithm || mode);
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    body: useForm ? form : undefined,
    headers: useForm ? {} : { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getAnalyzeStatus(jobId) {
  const res = await fetch(`${API_BASE}/analyze/${jobId}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getReport(jobId) {
  const res = await fetch(`${API_BASE}/analyze/${jobId}/report`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getPatches(jobId) {
  const res = await fetch(`${API_BASE}/analyze/${jobId}/patches`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getDocPreprocess(jobId) {
  const res = await fetch(`${API_BASE}/analyze/${jobId}/docs`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getFile(jobId, path) {
  const params = new URLSearchParams({ path });
  const res = await fetch(`${API_BASE}/analyze/${jobId}/file?${params.toString()}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getFiles(jobId) {
  const res = await fetch(`${API_BASE}/analyze/${jobId}/files`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getFileAst(jobId, path) {
  const res = await fetch(
    `${API_BASE}/analyze/${jobId}/ast?path=${encodeURIComponent(path)}`
  );
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getSymbolGraph(jobId) {
  const res = await fetch(`${API_BASE}/analyze/${jobId}/symbol-graph`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getFileContent(jobId, path) {
  const res = await fetch(
    `${API_BASE}/analyze/${jobId}/file?path=${encodeURIComponent(path)}`
  );
  if (!res.ok) throw new Error(await res.text());
  return res.text();
}

export async function health() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}
