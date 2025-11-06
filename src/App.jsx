import React, { useState } from "react";
import Chart from "chart.js/auto";

export default function LogProcessor() {
  const [rawText, setRawText] = useState("");
  const [records, setRecords] = useState([]);
  const [anomalies, setAnomalies] = useState({ bruteForce: [], portScans: [], suspiciousIPs: [] });
  const [summary, setSummary] = useState({ total: 0 });

  //przykładowa  czarna lista
  const localBlacklist = ["203.0.113.45", "198.51.100.23"];

  //funkcja pomocnicza do parsowania daty ze stringa
  function parseTimestamp(s) {
    const d = new Date(s);
    if (!isNaN(d)) return d;
    const m = s.match(/^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}/); // "Nov 06 09:12:04"
    if (m) return new Date(`${m[0]} 2025`); // dodaj rok bieżący
  }
  

  //próba sparsowania jednej linii logu w CLF lub key=value
  function parseLogLine(line) {
    line = line.trim();
    if (!line) return null;

    //1) JSON
    if (line.startsWith("{") && line.endsWith("}")) {
      try {
        const obj = JSON.parse(line);
        return normalizeRecord(obj);
      } catch (e) {
        return null;
      }
    }

    //2) CSV: ip,time,request,status,port
    const csvParts = line.split(",");
    if (csvParts.length >= 3 && csvParts[0].match(/^\d+\.\d+\.\d+\.\d+$/)) {
      const [src, time, request, status, port] = csvParts.map((p) => p.trim());
      return normalizeRecord({ srcIP: src, time, request, status, port });
    }

    //3) CLF: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    const clfMatch = line.match(/^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d{3}) (\d+|-)$/);
    if (clfMatch) {
      const srcIP = clfMatch[1];
      const time = clfMatch[2];
      const request = clfMatch[3];
      const status = clfMatch[4];
      return normalizeRecord({ srcIP, time, request, status });
    }

    //4) Key=Value style: src=1.2.3.4 dst=5.6.7.8 port=22 status=Failed
    const kv = {};
    const kvPairs = line.match(/(\w+=[^\s]+)/g);
    if (kvPairs) {
      kvPairs.forEach((p) => {
        const [k, v] = p.split("=");
        kv[k] = v;
      });
      return normalizeRecord(kv);
    }

    //5) Syslog-like: "Nov 06 09:12:04 sshd[2145]: Failed password for invalid user admin from 198.51.100.23 port 45678 ssh2"
    const syslogMatch = line.match(/from (\d{1,3}(?:\.\d{1,3}){3}) port (\d+)/);
    if (syslogMatch) {
      const [_, srcIP, port] = syslogMatch;
      const timeMatch = line.match(/^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}/);
      const time = timeMatch ? timeMatch[0] : undefined;
      const failed = line.toLowerCase().includes("failed") || line.toLowerCase().includes("brute");
      const status = failed ? "Failed" : "OK";
      return normalizeRecord({ srcIP, port, time, status, request: line });
    }

    //6) Kernel or IDS logs
    const kernelMatch = line.match(/SRC=(\d{1,3}(?:\.\d{1,3}){3}).*DPT=(\d+)/);
    if (kernelMatch) {
      const [_, srcIP, port] = kernelMatch;
      const timeMatch = line.match(/^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}/);
      const time = timeMatch ? timeMatch[0] : undefined;
      return normalizeRecord({ srcIP, port, time, request: line });
    }


    //7) Fallback: próba znalezienia IP i timestampa
    const ip = line.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    const ts = line.match(/\[(.*?)\]/);
    return normalizeRecord({ srcIP: ip ? ip[1] : undefined, time: ts ? ts[1] : undefined, raw: line });
  }

  //normalizacja pola rekordu do przewidywalnego formatu
  function normalizeRecord(obj) {
    const r = {
      srcIP: obj.srcIP || obj.ip || obj.client || obj.src || obj.source,
      destIP: obj.destIP || obj.dst || obj.destination || obj.server || obj.dest,
      time: obj.time || obj.timestamp || obj.ts || obj.date,
      request: obj.request || obj.method || obj.msg,
      status: obj.status || obj.code || obj.result,
      port: obj.port ? Number(obj.port) : obj.destination_port ? Number(obj.destination_port) : undefined,
      raw: obj.raw || JSON.stringify(obj),
    };
    //parsowanie timestampa
    r.parsedTime = r.time ? parseTimestamp(r.time) : null;
    return r;
  }

  //funkcja główna do parsowania całego tekstu pliku
  function parseText(text) {
    const lines = text.split(/\r?\n/);
    const recs = lines.map(parseLogLine).filter(Boolean);
    setRecords(recs);
    setSummary({ total: recs.length });
    detectAnomalies(recs);
  }

  //wykrywanie prostych anomalii
  function detectAnomalies(recs) {
    const now = Date.now();

    //Brute force: duża liczba nieudanych prób logowania z jednego adresu IP
    //Heurystyka: jeśli dla IP > N prób z status 'Failed' lub status kod 401/403 w oknie T sekund
    const BF_THRESHOLD = 5; //próg liczby prób
    const BF_WINDOW_MS = 1 * 60 * 1000; //15 minut

    const byIP = {};
    recs.forEach((r) => {
      const ip = r.srcIP || "unknown";
      if (!byIP[ip]) byIP[ip] = [];
      byIP[ip].push(r);
    });

    const bruteForceFindings = [];
    Object.entries(byIP).forEach(([ip, arr]) => {
      //sortuj po czasie
      const times = arr
        .map((x) => ({ t: x.parsedTime ? x.parsedTime.getTime() : null, status: x.status, raw: x }))
        .sort((a, b) => (a.t || 0) - (b.t || 0));

      // sliding window count of failures
      for (let i = 0; i < times.length; i++) {
        const start = times[i].t || now;
        let count = 0;
        for (let j = i; j < times.length; j++) {
          const t = times[j].t || now;
          if (t - start <= BF_WINDOW_MS) {
            const st = (times[j].status || "").toString().toLowerCase();
            if (st.includes("fail") || st === "401" || st === "403" || st.includes("unauthorized")) count++;
          } else break;
        }
        if (count >= BF_THRESHOLD) {
          bruteForceFindings.push({ ip, firstSeen: new Date(start).toISOString(), attempts: count });
          break;
        }
      }
    });

    //Port scanning: wiele prób na różnych portach w krótkim czasie
    //Heurystyka: dla jednego srcIP wykryj liczbę unikalnych portów >= P w oknie W
    const PS_THRESHOLD = 20;
    const PS_WINDOW_MS = 5 * 60 * 1000; //5 minut

    const portScans = [];
    Object.entries(byIP).forEach(([ip, arr]) => {
      const withPorts = arr.filter((r) => r.port && !isNaN(r.port));
      if (withPorts.length === 0) return;
      const times = withPorts
        .map((x) => ({ t: x.parsedTime ? x.parsedTime.getTime() : now, port: x.port }))
        .sort((a, b) => a.t - b.t);

      for (let i = 0; i < times.length; i++) {
        const start = times[i].t;
        const ports = new Set();
        for (let j = i; j < times.length; j++) {
          if (times[j].t - start <= PS_WINDOW_MS) {
            ports.add(times[j].port);
          } else break;
        }
        if (ports.size >= PS_THRESHOLD) {
          portScans.push({ ip, firstSeen: new Date(start).toISOString(), uniquePorts: ports.size, samplePorts: Array.from(ports).slice(0, 10) });
          break;
        }
      }
    });

    //Podejrzane adresy IP: czarna lista
    const suspicious = recs
      .map((r) => r.srcIP)
      .filter(Boolean)
      .filter((ip, idx, arr) => localBlacklist.includes(ip))
      .map((ip) => ({ ip }));

    setAnomalies({ bruteForce: bruteForceFindings, portScans, suspiciousIPs: suspicious });
  }

  //handler wczytania pliku przez input[type=file]
  function handleFileChange(e) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target.result;
      setRawText(text);
      parseText(text);
    };
    reader.readAsText(file);
  }

  //Proste API: eksport wyników jako CSV
  function exportCSV() {
    if (!records.length) return;
    const headers = ["srcIP", "destIP", "time", "request", "status", "port"];
    const lines = [headers.join(",")].concat(records.map((r) => headers.map((h) => JSON.stringify(r[h] ?? "")).join(",")));
    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "parsed_logs.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ padding: 12, fontFamily: "system-ui, Arial" }}>
      <h2>Wybierz plik .log / .csv / .json</h2>
      <input type="file" accept=".log,.txt,.csv,.json" onChange={handleFileChange} />

      <div style={{ marginTop: 12 }}>
        <strong>Podsumowanie:</strong>
        <div>Liczba rekordów: {summary.total}</div>
        <div>Wykryte brute-force: {anomalies.bruteForce.length}</div>
        <div>Wykryte port-scan: {anomalies.portScans.length}</div>
        <div>Podejrzane na czarnej liście: {anomalies.suspiciousIPs.length}</div>
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={exportCSV} disabled={!records.length}>Eksportuj CSV</button>
      </div>

      <details style={{ marginTop: 12 }}>
        <summary>Podgląd rekordów (pierwsze 50)</summary>
        <pre style={{ maxHeight: 320, overflow: "auto" }}>{JSON.stringify(records.slice(0, 50), null, 2)}</pre>
      </details>

      <details style={{ marginTop: 12 }}>
        <summary>Wykryte anomalie</summary>
        <div>
          <h4>Brute-force</h4>
          <pre>{JSON.stringify(anomalies.bruteForce, null, 2)}</pre>
          <h4>Port scans</h4>
          <pre>{JSON.stringify(anomalies.portScans, null, 2)}</pre>
          <h4>Blacklisted IPs</h4>
          <pre>{JSON.stringify(anomalies.suspiciousIPs, null, 2)}</pre>
        </div>
      </details>

      <div style={{ marginTop: 12 }}>
        <em>Na potem:</em>
        <ul>
          <li>napraw działanie port scana</li>
          <li>zamień anomalie na na chart.js</li>
          <li>thresholdy zmieniaj w funkcjach wykrywania anomalii</li>
        </ul>
      </div>
    </div>
  );
}
